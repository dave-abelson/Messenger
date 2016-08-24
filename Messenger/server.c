//HW6 server file
//server program by Dave Abelson
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <getopt.h>
#include <semaphore.h>
#include "sfwrite.c"

#define WOLFIE_MSG "WOLFIE \r\n\r\n"
#define EIFLOW_MSG "EIFLOW \r\n\r\n"
#define IAM_MSG "IAM "
#define IAMNEW_MSG "IAMNEW "
#define NEWPASS_MSG "NEWPASS"
#define SSAPWEN_MSG "SSAPWEN \r\n\r\n"
#define TIME_MSG "TIME \r\n\r\n"
#define BYE_MSG "BYE \r\n\r\n"
#define UOFF_MSG "UOFF "
#define LISTU_MSG "LISTU \r\n\r\n"
#define ERROR_USER_NAME_MSG "ERR 00 USERNAME TAKEN \r\n\r\n"
#define ERROR_PWD "ERR 02 BAD PASSWORD \r\n\r\n"
#define ERROR_01 "ERR 01 USER NOT AVAILABLE \r\n\r\n"
#define ERROR_100 "ERR 100 \r\n\r\n"
#define INVALID_PROTOCOL_MSG "INVALID PROTOCOL \r\n\r\n"
#define END_MSG " \r\n\r\n"
#define UTSIL_MSG "UTSIL "
#define USER_SPACE_MSG " \r\n "
#define PASSWORD_MSG "SSAP \r\n\r\n"
#define DEFAULT_COLOR "\x1B[0m"
#define VERBOSE_COLOR "\x1B[1;34m"
#define DEFAULT "DEFAULT"
#define VERBOSE "VERBOSE"

#define MAX_CLIENTS 30
#define BUFFERSIZE 1024
#define TRUE 1
#define FALSE 0

int verbose = 0;
int thread_count = 0;
int client_sockets[MAX_CLIENTS];
fd_set fdset, commfd;
FILE *fp;
char *file;
char *motd;
int commbool = 0;
pthread_mutex_t R_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t list_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t acct_lock = PTHREAD_RWLOCK_INITIALIZER;
int piped[2];
int commClients[MAX_CLIENTS];
pthread_mutex_t printLock;

void sigint_handler(int sig);
void printServerHelpMenu();
void printServerMenu();
void *loginHandler();
ssize_t Recv(int sockfd, char buf[]);
int sendClientRequest(char* output, int client_socket);
void changeTextColor(char *colorName);
void deleteClient(int client_socket);
void sha256(char *password, char outputBuffer[65]);
void *communication();
void fillfd();

typedef struct{
	int qBuffer[BUFFERSIZE];
	int tail, head;
	int empty, full;
} queue;

void clearQueue(queue *q){
	free(q);
}

queue* initQueue(void){
	queue *q = (queue *)malloc(sizeof(queue));
	if(q == NULL){
		perror("Failed to allocate memory.");
	}

	q->empty = TRUE;
	q->full = FALSE;
	q->head = q->tail = 0;

	return q;
}

void push(queue *q, int fd){
	q->qBuffer[q->tail] = fd;
	q->tail++;
	q->empty = FALSE;
	if(q->tail == BUFFERSIZE){
		q->full = TRUE;
	}
}

int pop(queue *q){
	int fd = q->qBuffer[q->head];
	q->head++;
	if(q->head == q->tail){
		q->empty = TRUE;
	}
	return fd;
}

//active user list
struct userNode{
	char *name;
	int fd;
	time_t start;
	struct userNode *next;
	struct userNode *prev;
};

typedef struct userNode userNode_t;

struct userList{
	userNode_t *head;
	userNode_t *tail;
	unsigned int size;
};

typedef struct userList userList_t;

userList_t* masterList;

//user list functions
userList_t* userListInit(void){
	pthread_rwlock_wrlock(&list_lock);
	userList_t* ul = (userList_t*)malloc(sizeof(userList_t));
	if(ul == NULL){
		perror("Failed to allocate memory.");
		exit(EXIT_FAILURE);
	}
	ul->head = NULL;
	ul->tail = NULL;
	ul->size = 0;
	pthread_rwlock_unlock(&list_lock);
	return ul;
}

int userListAppend(userList_t *ul, char *name, int fd){
	//pthread_mutex_lock(&R_lock);
	pthread_rwlock_wrlock(&list_lock);
	//printf("APPENDING %s port: %d\n", name, fd);
	userNode_t* k = masterList->head;
	while(k != NULL){
		if(!strcmp(k->name, name)){
			//same name
			sendClientRequest(ERROR_USER_NAME_MSG, fd);
			sendClientRequest(BYE_MSG, fd);
			//deleteClient(client_socket);
			close(fd);
			return -1;
		}
		k = k->next;
	}
	userNode_t* newUser = (userNode_t*)malloc(sizeof(userNode_t));
	newUser->name = name;
	newUser->fd = fd;
	newUser->start = time(0);
	//check if invalid

	if(ul == NULL){
		return -1;
	}
	//check if empty
	if(ul->head == NULL){
		ul->head = newUser;
		ul->tail = newUser;
	}
	else{
		newUser->next = ul->head;
		ul->head->prev = newUser;
	}
	newUser->prev = NULL;
	ul->head = newUser;

	ul->size++;
	//pthread_mutex_unlock(&R_lock);
	pthread_rwlock_unlock(&list_lock);
	return 0;
}

int userListDeleteUser(userList_t *ul, userNode_t* n){
	pthread_rwlock_wrlock(&list_lock);

	//breaking into cases
	//tail
	if(n->next == NULL && n->prev != NULL){
		n->prev->next = NULL;
		ul->tail = n->prev;
		free(n);
	}
	//head
	else if(n->next != NULL && n->prev == NULL){
		n->next->prev = NULL;
		ul->head = n->next;
		free(n);
	}
	//only item
	else if(n->next == NULL && n->prev == NULL){
		ul->tail = NULL;
		ul->head = NULL;
		free(n);
	}
	//somewhere in middle
	else{
		n->prev->next = n->next;
		n->next->prev = n->prev;
		free(n);
	}
	ul->size--;

	pthread_rwlock_unlock(&list_lock);
	return 0;
}


pthread_mutex_t Q_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t items_sem;
queue *loginQueue;

int main(int argc, char *argv[]){
	int opt;
	int operation = TRUE;
	struct sockaddr_in serverAddr;
	int server_socket, client_socket, max_cd, activity;
	int port, i;
	char input[BUFFERSIZE];
	pthread_mutex_init(&printLock, NULL);

	masterList = userListInit();

	if(signal(SIGINT, sigint_handler) == SIG_ERR){
		exit(1);
	}
	signal(SIGPIPE, SIG_IGN);
	//handles command line args
	while((opt = getopt(argc, argv, "hvt:")) != -1){
		switch (opt){
			case 'h':
				printServerHelpMenu();
				return EXIT_SUCCESS;
				break;
			case 'v':
				verbose = 1;
				break;
			case 't':
				thread_count = atoi(optarg);
				break;
			default:
				printServerHelpMenu();
				return EXIT_SUCCESS;
		}
	}

	//printf("verbose =%d; thread_count=%d; optind=%d\n", verbose, thread_count, optind);

	if(optind >= argc){
		//fprintf(stderr, "Expected arguments after options\n");
		sfwrite(&printLock, stdout, "Expected arguments after options\n");
		return EXIT_SUCCESS;
	}
	port = atoi(argv[optind++]);
	motd = argv[optind++];
	file = argv[optind];

	fp = fopen(file, "a+");
	if(fp == NULL){
		fp = fopen(file, "r+");
	}
	fclose(fp);

	//printf("MOTD: %s\n", motd);
	sfwrite(&printLock, stdout, "MOTD: %s\n", motd);

	
	//done handling command line args

	//spawn login threads
	if(thread_count == 0){
		thread_count = 2;
	}
	//printf("THREAD COUNT: %d\n", thread_count);
	sfwrite(&printLock, stdout, "THREAD COUNT: %d\n", thread_count);
	sem_init(&items_sem, 0, 0);

	for(i = 0; i < thread_count; i++){
		pthread_t loginThread;
		pthread_create(&loginThread, NULL, (void *) &loginHandler, NULL);
	}

	//initializing queue
	loginQueue = initQueue();
	memset(&client_sockets[0], 0, MAX_CLIENTS);

	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0){
		//perror("Server Socket Failed.\n");
		sfwrite(&printLock, stdout, "Server Socket Failed\n");
		return EXIT_FAILURE;
	}

	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&operation, sizeof(operation)) < 0){
		//perror("Set Socket Operation Failed.");
		sfwrite(&printLock, stdout, "Set Socket Operation Failed\n");
		return EXIT_FAILURE;
	}

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = INADDR_ANY;
	serverAddr.sin_port = htons(port);
	//bind socket
	if(bind(server_socket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0){
		sfwrite(&printLock, stdout, "Bind Failed\n");
		//perror("Bind Failed.");
		return EXIT_FAILURE;
	}
	// fprintf(stderr, "Currently listening on port %d\n", port);
	sfwrite(&printLock, stdout, "Currently listening on port %d\n", port);

	if(listen(server_socket, 3) < 0){
		//perror("Listening Failed.");
		sfwrite(&printLock, stdout, "Listening Failed.\n");
		return EXIT_FAILURE;
	}

	//printf("Waiting for connections...\n");
	sfwrite(&printLock, stdout, "Waiting for connections...\n");

	//create init pipe
	if(pipe(piped) == -1){
		//perror("Pipe");
		sfwrite(&printLock, stdout, "Pipe Error\n");
		return EXIT_FAILURE;
	}

	while(TRUE){
		FD_ZERO(&fdset);
		FD_SET(STDIN_FILENO, &fdset);
		FD_SET(server_socket, &fdset);
		max_cd = server_socket;
		// for(i = 0; i < MAX_CLIENTS; i++){
		// 	cd = client_sockets[i];
		// 	if(cd > 0){
		// 		FD_SET(cd, &fdset);
		// 	}
		// 	if(cd > max_cd){
		// 		max_cd = cd;
		// 	}
		// }
		activity = select(max_cd + 1, &fdset, NULL, NULL, NULL);

		if((activity < 0) && (errno != EINTR)){
			printf("HERE\n");
			//printf("Select Error.");
			sfwrite(&printLock, stdout, "Select Error\n");
		}
		//checking for incoming connection
		if(FD_ISSET(server_socket, &fdset)){
			//if((client_socket = accept(server_socket, (struct sockaddr *) &serverAddr, (socklen_t*) &serverAddr)) < 0){
			if((client_socket = accept(server_socket, NULL, NULL)) < 0){
				//perror("Accept Failure.");
				sfwrite(&printLock, stdout, "Accept Failure\n");
				return EXIT_FAILURE;
			}
			//fprintf(stderr, "Server accepted new client. Socket: %d\n", client_socket);
			sfwrite(&printLock, stdout, "Server accepted new client. Socket: %d\n", client_socket);

			for(i = 0; i < MAX_CLIENTS; i++){
				if(client_sockets[i] == 0){
					client_sockets[i] = client_socket;
					break;
				}
			}
			//add client to queue
			pthread_mutex_lock(&Q_lock);
			//insert
			push(loginQueue, client_socket);

			pthread_mutex_unlock(&Q_lock);
			sem_post(&items_sem);

		}
		if(FD_ISSET(STDIN_FILENO, &fdset)){
			//handle server commands
			memset(&input[0], 0, BUFFERSIZE);
			fgets(input, BUFFERSIZE, stdin);

			if(!strcmp(input, "/users\n")){
				userNode_t* k = masterList->head;
				while(k != NULL){
					//fprintf(stderr, "%s\t", (char*)k->name);
					//printf("%d\n", k->fd);
					sfwrite(&printLock, stdout, "user:%s\tfd:%d\n", (char *)k->name, k->fd);
					k = k->next;
				}

			}
			else if(!strcmp(input, "/help\n")){
				printServerMenu();
			}
			else if(!strcmp(input, "/shutdown\n")){
				userNode_t* k = masterList->head;
				while(k != NULL){
					deleteClient(k->fd);
					k = k->next;
				}
				kill(0, SIGKILL);
			}
			else if(!strcmp(input, "/accts\n")){
				pthread_rwlock_rdlock(&acct_lock);
				char *line = NULL;
				size_t length = 0;
				ssize_t red;
				FILE *accts;
				char *disname;
			
				char *words[3];

				accts = fopen(file, "r");

				while((red = getline(&line, &length, accts)) != -1){
					words[0] = strtok(line, " ");
					words[1] = strtok(NULL, " ");
					words[2] = strtok(NULL, " ");

					disname = words[0];
					//fprintf(stderr, "NAME: %s\n", disname);
					sfwrite(&printLock, stdout, "NAME: %s\n", disname);

				
					//printf("\n");
				}			
				fclose(accts);
	    		pthread_rwlock_unlock(&acct_lock);
			}

		}


	}//end while
	
	return EXIT_SUCCESS;
	
}

void *loginHandler(){
	//retrieve client info from queue
	// printf("Going to get client from queue.\n");
	sfwrite(&printLock, stdout, "Going to get client from queue.\n");
	int client_socket;
	char received[BUFFERSIZE];
	char *parsePtr;
	char output[BUFFERSIZE];

	char inputName[BUFFERSIZE];
	unsigned char salt[16];
	unsigned char inSalt[16];

	char *disname;
	char *passwurd;
	unsigned char newSalt[16];
	fd_set loginfd;



	while(TRUE){
		sem_wait(&items_sem);
		pthread_mutex_lock(&Q_lock);
		// Remove request from queue
		client_socket = pop(loginQueue);
		pthread_mutex_unlock(&Q_lock);
		FD_ZERO(&loginfd);
		FD_SET(client_socket, &loginfd);

		int selectivity = select(client_socket + 1, &loginfd, NULL, NULL, NULL);

		if((selectivity < 0) && (errno != EINTR)){
			//printf("Select Error.");
			sfwrite(&printLock, stdout, "Select Error\n");
		}

		// printf("LOGGING IN: %d\n", client_socket);
		sfwrite(&printLock, stdout, "LOGGING IN: %d\n", client_socket);
		int protocol = 0;
		// Perform login protocol
		// If login successful add the user to the user list
		// Don't forget to protect your user list!!!!
		while(TRUE){
			if(protocol == 3){
				protocol = 0;
				break;
			}
			if(FD_ISSET(client_socket, &loginfd)){
				memset(&received[0], 0, BUFFERSIZE);
				Recv(client_socket, received);
				parsePtr = strstr(received, "\r\n\r\n");
				if(parsePtr == NULL){
					sendClientRequest(ERROR_100, client_socket);
					sendClientRequest(BYE_MSG, client_socket);
					deleteClient(client_socket);
					protocol = 3;
					break;
				}
				parsePtr[-1] = '\0';
				if(verbose == 1 && received != NULL){
					changeTextColor(VERBOSE);
		    		// fprintf(stderr, "RECEIVED: %s FROM: %d\n", received, client_socket);
		    		sfwrite(&printLock, stdout, "RECEIVED: %s FROM: %d\n", received, client_socket);
		    		changeTextColor(DEFAULT);
				}
			
				char *serverSig[BUFFERSIZE];
				memset(&serverSig[0], 0 , BUFFERSIZE);
			   	for(int i = 0; i < BUFFERSIZE; i++){
			    	serverSig[i] = calloc(BUFFERSIZE, BUFFERSIZE);
			    }
			    //didMalloc = 1;
			    char *atemp;
			    int ctr = 0;
			    for(atemp = strtok(received, " "); atemp; atemp = strtok(NULL, " ")){
			    	strcpy(serverSig[ctr], atemp);
			    	//printf("SERVERSIG: %s CTR: %d \n", serverSig[ctr], ctr);
			    	ctr++;
			    }

			    // if(verbose == 1){
			    // 	changeTextColor(VERBOSE);
			    // 	// fprintf(stderr, "RECEIVED: %s FROM: %d\n", serverSig[0], client_socket);
			    // 	sfwrite(&printLock, stdout, "RECEIVED: %s FROM: %d\n", serverSig[0], client_socket);
			    // 	changeTextColor(DEFAULT);
			    // }


				if(!strcmp(serverSig[0], "WOLFIE")){
					strcpy(output, EIFLOW_MSG);
					if(client_socket != 0 && sendClientRequest(output, client_socket) == 0){
						//perror("Failed to write.");
						sfwrite(&printLock, stdout, "Failed to write.");
					}
					protocol = 1;			
				}
				else if((!strcmp(serverSig[0], "IAMNEW")) && protocol == 1){
					int samename = 0;
					pthread_rwlock_rdlock(&acct_lock);
					userNode_t* newNode = masterList->head;
					while(newNode != NULL){
						if(strcmp(newNode->name, serverSig[1]) == 0){
							sendClientRequest(ERROR_USER_NAME_MSG, client_socket);
							sendClientRequest(BYE_MSG, client_socket);
							deleteClient(client_socket);
							close(client_socket);
							protocol = 3;
							samename = 1;
							break;
						}
						newNode = newNode->next;
					}
					pthread_rwlock_unlock(&acct_lock);
					if(samename == 1){
						samename = 0;
						protocol = 3;
						break;
					}
					int x = userListAppend(masterList, serverSig[1], client_socket);
					if(x == -1){
						protocol = 3;
						break;
					}
					char nbuf[BUFFERSIZE];
					char nbuf1[BUFFERSIZE];
					char nbuf2[BUFFERSIZE];
					char *nline = NULL;
					size_t nlength = 0;
					ssize_t nred;
					int nameyName;
					pthread_rwlock_rdlock(&acct_lock);
					if(fp == NULL){
						sendClientRequest(ERROR_100, client_socket);
						deleteClient(client_socket);
						protocol = 3;
						break;
					}

					fp = fopen(file, "r");

					while((nred = getline(&nline, &nlength, fp)) != -1){
						if(nline[0] <= 0){
							break;
						}
						memset(&nbuf[0], 0, BUFFERSIZE);
						memset(&nbuf1[0], 0, BUFFERSIZE);
						memset(&nbuf2[0], 0, BUFFERSIZE);
						char *nfirstspace = strstr(nline, " ");
						char *nsecondspace = strstr(&nfirstspace[1], " "); 
						long int nlineLength = nfirstspace - nline;
						long int nlineLength2 = nsecondspace - (nfirstspace + 1);

						strncpy(nbuf, nline, nlineLength);

						strncpy(nbuf1, &nfirstspace[1], nlineLength2);

						strcpy(nbuf2, &nsecondspace[1]);
						if(!strcmp(nbuf, serverSig[1])){
							nameyName = 1;
							break;
						}
					}
		    		fclose(fp);
		    		pthread_rwlock_unlock(&acct_lock);
		    		if(nameyName == 1){
		    			protocol = 0;
						sendClientRequest(ERROR_USER_NAME_MSG, client_socket);
						close(client_socket);
						protocol = 3;
						break;
					}
					if(newNode == NULL){
						memset(&output[0], 0, BUFFERSIZE);
						strcpy(output, "HINEW ");
						strcat(output, serverSig[1]);
						strcpy(inputName, serverSig[1]);
						strcat(output, END_MSG);
						sendClientRequest(output, client_socket);
						memset(&output[0], 0, BUFFERSIZE);
					}
					protocol = 2;
				}
				else if((!strcmp(serverSig[0], "NEWPASS")) && protocol == 2){
					char *pass = serverSig[1];
					int upper = 0;
					int symbol = 0;
					int numberp = 0;
					int j;
					int plen = strlen(pass);
					//at least 5 chars
					if(plen < 5){
						sendClientRequest(ERROR_PWD, client_socket);
						deleteClient(client_socket);
					}
					for(j = 0; j < plen; j++){
						if(pass[j] > 64 && pass[j] < 91){
							upper = 1;
						}
						if((pass[j] > 32 && pass[j] < 48) || (pass[j] > 57 && pass[j] < 65) ||
							(pass[j] > 90 && pass[j] < 97) || (pass[j] > 122 && pass[j] < 127)){
							symbol = 1;
						}
						if(pass[j] > 47 && pass[j] < 58){
							numberp = 1;
						}
					}
					if(upper == 1 && symbol == 1 && numberp == 1){
						memset(&output[0], 0, BUFFERSIZE);
						sendClientRequest(SSAPWEN_MSG, client_socket);
						strcpy(output, "HI ");
						strcat(output, inputName);
						strcat(output, END_MSG);
						sendClientRequest(output, client_socket);
						pthread_rwlock_rdlock(&acct_lock);
						userNode_t* newNode = masterList->head;
						while(newNode != NULL){
							// if(strcmp(newNode->name, inputName) == 0){
							// 	sendClientRequest(ERROR_USER_NAME_MSG, client_socket);
							// 	sendClientRequest(BYE_MSG, client_socket);
							// 	deleteClient(client_socket);
							// 	protocol = 0;
							// 	break;
							// }
							newNode = newNode->next;
						}
						pthread_rwlock_unlock(&acct_lock);
						if(newNode == NULL){

							memset(&output[0], 0, BUFFERSIZE);

							// pthread_mutex_lock(&R_lock);
							char *anotherbufferagain = (char *) calloc(strlen(inputName) + 1, 1);
							strcpy(anotherbufferagain, inputName);


							// int x = userListAppend(masterList, anotherbufferagain, client_socket);
							// if(x == -1){
							// 	//printf("BROKE\n");
							// 	protocol = 3;
							// 	break;
							// }
							// fillfd();
							// pthread_mutex_unlock(&R_lock);

							//WRITE NAME AND PASSWORD TO FILE
							pthread_rwlock_wrlock(&acct_lock);
							strcpy(output, inputName);
							strcat(output, " ");
							char outputBuffer [256];
							char *passSalt = malloc(256);
							memset(&passSalt[0],0,256);
							RAND_bytes(salt, 16);
							while(strstr((char *) salt, "\n") != NULL || strstr((char *) salt, " ") != NULL){
								RAND_bytes(salt, 16);
							}

							strcpy(passSalt, pass);
									
							snprintf(passSalt, 256, "%s%s", pass, salt);
							sha256(passSalt, outputBuffer);

							strcat(output, outputBuffer);

							strcat(output, " ");
							fp = fopen(file, "a+");
							if(fp == NULL){
								fp = fopen(file, "r+");
							}
							fprintf(fp, "%s", output);
							fprintf(fp, "%s\n", salt);

							fclose(fp);
							pthread_rwlock_unlock(&acct_lock);

						}
						memset(&output[0], 0, BUFFERSIZE);

						strcpy(output, "MOTD ");
						strcat(output, motd);
						strcat(output, END_MSG);
						sendClientRequest(output, client_socket);
						
						fillfd();
						write(piped[1], "\r\0", 2);

						protocol = 3;

						if(commbool == 0){
							pthread_t commThread;
							pthread_create(&commThread, NULL, (void *) &communication, NULL);
							commbool = 1;
						}

					}	
					else{
						sendClientRequest(ERROR_PWD, client_socket);
						deleteClient (client_socket);
						protocol = 0;
						break;
					}
				}
				else if((!strcmp(serverSig[0], "IAM")) && protocol == 1){
						int samename = 0;
						pthread_rwlock_rdlock(&acct_lock);
						userNode_t* p = masterList->head;
						while(p != NULL){
							if(strcmp(p->name, serverSig[1]) == 0){
								sendClientRequest(ERROR_USER_NAME_MSG, client_socket);
								deleteClient(client_socket);
								protocol = 3;
								samename = 1;
								break;
							}
							p = p->next;
						}
						pthread_rwlock_unlock(&acct_lock);
						if(samename == 1){
							samename = 0;
							break;
						}
						int y =userListAppend(masterList, serverSig[1], client_socket);
						if(y == -1){
							break;
						}
					

						memset(&output[0], 0, BUFFERSIZE);
						//read through file to see if user exists
						//then checks password
						char *line = NULL;
						size_t length = 0;
						ssize_t red;
						char buf[BUFFERSIZE];
						char buf1[BUFFERSIZE];
						char buf2[BUFFERSIZE];
						int nameExists = 0;
						pthread_rwlock_rdlock(&acct_lock);
						if(fp == NULL){
							sendClientRequest(ERROR_100, client_socket);
							protocol = 3;
							close(client_socket);
							break;
						}
						fp = fopen(file, "r");
					
						while((red = getline(&line, &length, fp)) != -1){
							if(line[0] <= 0){
								break;
							}
							memset(&buf[0], 0, BUFFERSIZE);
							memset(&buf1[0], 0, BUFFERSIZE);
							memset(&buf2[0], 0, BUFFERSIZE);
							
							char *firstspace = strstr(line, " ");
							char *secondspace = strstr(&firstspace[1], " "); 

							long int lineLength = firstspace - line;
							long int lineLength2 = secondspace - (firstspace + 1);

							strncpy(buf, line, lineLength);

							strncpy(buf1, &firstspace[1], lineLength2);

							strcpy(buf2, &secondspace[1]);

							if(!strcmp(buf, serverSig[1])){
								strcpy((char*)inSalt, buf2);
								inSalt[strlen(buf2)-1] = '\0';
								passwurd = buf1;
								disname = buf;
								nameExists = 1;
								break;
							}
									
						}
		    			
		    			fclose(fp);
		    			pthread_rwlock_unlock(&acct_lock);
		    			
		    			if(nameExists == 0){
		    				printf("HERE\n");
							sendClientRequest(ERROR_01, client_socket);
							sendClientRequest(BYE_MSG, client_socket);
							close(client_socket);
							protocol = 3;
							break;
						}
		    			strcpy(output, "AUTH ");
		    			strcat(output, serverSig[1]);
		    			strcat(output, END_MSG);

						sendClientRequest(output, client_socket);
						memset(&output[0], 0, BUFFERSIZE);


				protocol = 2;

				}
				else if((!strcmp(serverSig[0], "PASS")) && protocol == 2){
					//check later
					strncpy((char *)newSalt, (char *)inSalt, 16);
					memset(&newSalt[0], 0, 16);
					passwurd[strcspn(passwurd, "\n")] = 0;
					//hash password with salt
					char *inPassSalt = malloc(256);
					char outinputBuffer [256];
					memset(&inPassSalt[0],0,256);
					snprintf(inPassSalt, 256, "%s%s", serverSig[1], inSalt);
					sha256(inPassSalt, outinputBuffer);
					if(strcmp(outinputBuffer, passwurd)){
						//incorrect password
						sendClientRequest(ERROR_PWD, client_socket);
						deleteClient(client_socket);
						protocol = 3;
						break;
					}
					else{//correct password
						memset(&output[0], 0, BUFFERSIZE);

						userNode_t* i = masterList->head;
						while(i != NULL){
							if(strcmp(i->name, inputName) == 0){
								sendClientRequest(ERROR_USER_NAME_MSG, client_socket);
								deleteClient(client_socket);
								protocol = 3;
								break;
							}
							i = i->next;
						}
						if(i == NULL){
							memset(&output[0], 0, BUFFERSIZE);
							char *anotherbuffer = (char *) calloc(strlen(disname) + 1, 1);
							strcpy(anotherbuffer, disname);
							// pthread_mutex_lock(&R_lock);
							// int y =userListAppend(masterList, anotherbuffer, client_socket);
							// if(y == -1){
							// 	break;
							// }
							// fillfd();
							// //char *buffy = "\r\n";
							// write(piped[1], "\r\0", 2);
							//printf("WRITING TO PIPE\n");
							// pthread_mutex_unlock(&R_lock);
						}

						sendClientRequest(PASSWORD_MSG, client_socket);
						strcpy(output, "HI ");
						strcat(output, disname);
						strcat(output, END_MSG);
						sendClientRequest(output, client_socket);

						memset(&output[0], 0, BUFFERSIZE);
						strcpy(output, "MOTD ");
						strcat(output, motd);
						strcat(output, END_MSG);
						sendClientRequest(output, client_socket);
						protocol = 3;

						fillfd();
						write(piped[1], "\r\0", 2);

						if(commbool == 0){
							pthread_t commThread;
							pthread_create(&commThread, NULL, (void *) &communication, NULL);
							commbool = 1;
						}
						
					}
				}
			}		

		}

	}

	return (void *) NULL;
}

void *communication(){
	fd_set ready_set;
	int i, selection;
	//int max_sd = 0;
	char received[BUFFERSIZE];
	char untouched[BUFFERSIZE];
	char output[BUFFERSIZE];
	char *parsePtr;

	while(TRUE){
		// int max_sd = 0;
		userNode_t* z = masterList->head;
		if(z == NULL){ 
			commbool = 0;
			return (void*) NULL; 
		}
		int sd = 0;
		ready_set = commfd;
		selection = select(25 + 1, &ready_set, NULL, NULL, NULL);
		//printf("LOW\n");
		if((selection < 0) && (errno != EINTR)){
			sfwrite(&printLock, stdout, "Select Error.\n");
			//printf("Select Error.\n");
		}
		if(FD_ISSET(piped[0], &ready_set)){
			//	printf("PIPED\n");
			char blank[BUFFERSIZE];
			read(piped[0], blank, BUFFERSIZE);
			//printf("%s\n", blank);
		}
		for(i = 0; i < MAX_CLIENTS; i++){
			sd = commClients[i];

			if(FD_ISSET(sd, &ready_set)){
				memset(&received[0], 0, BUFFERSIZE);
				Recv(sd, received);
				//printf("received: %s from: %d\n", received, sd);
				strcpy(untouched, received);
				parsePtr = strstr(received, "\r\n\r\n");
				if(parsePtr == NULL){
					sendClientRequest(ERROR_100, sd);
					deleteClient(sd);
				}
				parsePtr[-1] = '\0';
				if(verbose == 1 && received != NULL){
					changeTextColor(VERBOSE);
	    			// fprintf(stderr, "RECEIVED: %s FROM: %d\n", received, sd);
	    			sfwrite(&printLock, stdout, "RECEIVED: %s FROM: %d\n", received, sd);
	    			changeTextColor(DEFAULT);
	    		}
	    		break;
			}
		}

		char *serverSig[BUFFERSIZE];
		memset(&serverSig[0], 0, BUFFERSIZE);
	   	for(int i = 0; i < BUFFERSIZE; i++){
	    	serverSig[i] = calloc(BUFFERSIZE, BUFFERSIZE);
	    }
	    char *atemp;
	    int ctr = 0;
	    for(atemp = strtok(received, " "); atemp; atemp = strtok(NULL, " ")){
	    	strcpy(serverSig[ctr], atemp);
	    	ctr++;
	    }


		if(strcmp(serverSig[0], "TIME") == 0){
			int tiempo;
			userNode_t* k = masterList->head;
			while(k != NULL){
				if(k->fd == sd){
					tiempo = k->start;
					break;
				}
				k = k->next;
			}
			int elapsed_time = difftime(time(0), tiempo);
			char elapsed_time_string[10];
			snprintf(elapsed_time_string, 10, "%d", elapsed_time);
			memset(&output[0], 0, BUFFERSIZE);
			strcpy(output, "EMIT ");
			strcat(output, elapsed_time_string);
			strcat(output, END_MSG);

			sendClientRequest(output, sd);
					
			memset(&output[0], 0, BUFFERSIZE);

		}
		else if(strcmp(serverSig[0], "LISTU") == 0){
			memset(&output[0], 0, BUFFERSIZE);
			strcpy(output, UTSIL_MSG);
			userNode_t* i = masterList->head;
			while(i != NULL){
				strcat(output, (char*)i->name);
				//fprintf(stderr, "NAME: %s\n", (char*)i->name);
				i = i->next;
				if(i != NULL){
					strcat(output, USER_SPACE_MSG);
				}
			}
			strcat(output, END_MSG);
			sendClientRequest(output, sd);
			//fprintf(stderr, "Size is: %d\n", masterList->size);
			memset(&output[0], 0, BUFFERSIZE);

		}
		else if(strcmp(serverSig[0], "BYE") == 0){
			char *name;
			userNode_t* j = masterList->head;
			while(j != NULL){
				if(j->fd == sd){
					name = j->name;
				}
				j = j->next;
			}
			userNode_t* i = masterList->head;
			while(i != NULL){
				if(i->fd == sd){
					i=i->next;
					continue;
				}
				memset(&output[0], 0, BUFFERSIZE);
				strcpy(output, UOFF_MSG);
				strcat(output, name);
				strcat(output, END_MSG);
				sendClientRequest(output, i->fd);
				i = i->next;
			}
			deleteClient(sd);
			fillfd();
		}
		else if(!strcmp(serverSig[0], "MSG")){
			memset(&output[0], 0, BUFFERSIZE);

			char *toname;
			char *fromname;
			int tofd;
			int nameFound;
			toname = serverSig[1];
			fromname = serverSig[2];
			fprintf(stderr, "TO NAME: %s\n", toname);
			fprintf(stderr, "FROM NAME: %s\n", fromname);
			if(!strcmp(toname, fromname)){
				sendClientRequest(ERROR_01, sd);
			}
			userNode_t* i = masterList->head;
			while(i != NULL){
				printf("TESTING\n");
				// if(!strcmp(i->name, fromname)){
				// 	tofd = i->fd;
				// 	nameFound = 1;
				// 	printf("HI I am here\n");
				// }
				if(!strcmp(i->name, toname)){
					nameFound = 1;
					tofd = i->fd;
				}
				i = i->next;
			}

			if(nameFound == 0){
				sendClientRequest(ERROR_01 ,sd);
			}
			else{
				sendClientRequest(untouched, sd);
				sendClientRequest(untouched, tofd);
			}


		}

	}//end while
}

void sigint_handler(int sig){		
	int byefd;
	
	userNode_t* i = masterList->head;
	while(i != NULL){
		byefd = i->fd;
		sendClientRequest(BYE_MSG, byefd);
		close(byefd);
		i = i->next;
	}
	sfwrite(&printLock, stdout, "I got you, chief.\n");

	//printf("I gotchu homeboy\n");

	exit(0);
	return;
}

void printServerHelpMenu(){
	printf("\n");
	// printf("./server [-h|v] [-t THREAD_COUNT] PORT_NUMBER MOTD [ACCOUNTS_FILE]\n");
	// printf("-h\t\tDisplays this help menu, and returns EXIT_SUCCESS.\n");
	// printf("-t THREAD_COUNT\t\tThe number of threads used for the login queue.\n");
	// printf("-v\t\tVerbose print all incoming and outgoing protocol verbs & content.\n");
	// printf("PORT_NUMBER\tPort number to listen on.\n");
	// printf("MOTD\t\tMessage to display to the client when they connect.\n");
	// printf("ACCOUNTS_FILE\tFile containing username and password data to be loaded upon execution.\n");
	sfwrite(&printLock, stdout, "\n");
	sfwrite(&printLock, stdout, "./server [-h|v] [-t THREAD_COUNT] PORT_NUMBER MOTD [ACCOUNTS_FILE]\n");
	sfwrite(&printLock, stdout, "-h\t\tDisplays this help menu, and returns EXIT_SUCCESS.\n");
	sfwrite(&printLock, stdout, "-t THREAD_COUNT\t\tThe number of threads used for the login queue.\n");
	sfwrite(&printLock, stdout, "-v\t\tVerbose print all incoming and outgoing protocol verbs & content.\n");
	sfwrite(&printLock, stdout, "PORT_NUMBER\tPort number to listen on.\n");
	sfwrite(&printLock, stdout, "MOTD\t\tMessage to display to the client when they connect.\n");
	sfwrite(&printLock, stdout, "ACCOUNTS_FILE\tFile containing username and password data to be loaded upon execution.\n");

}

void printServerMenu(){
	// printf("\n");
	// printf("\x1B[1;36m");
	// fflush(stdout);
	// printf("----------Server Commands----------\n");
	// printf("/accts\t\t\tPrints list of accounts in the server.\n");
	// printf("/users\t\t\tPrints list of users using the server.\n");
	// printf("/help\t\t\tPrints the server commands.\n");
	// printf("/shutdown\t\t\tShuts the server down.\n");
	// printf("\x1B[0m");
	// fflush(stdout);
	// printf("\n");
	sfwrite(&printLock, stdout, "\n");
	sfwrite(&printLock, stdout, "\x1B[1;36m");
	fflush(stdout);
	sfwrite(&printLock, stdout, "----------Server Commands----------\n");
	sfwrite(&printLock, stdout, "/accts\t\t\tPrints list of accounts in the server.\n");
	sfwrite(&printLock, stdout, "/users\t\t\tPrints list of users using the server.\n");
	sfwrite(&printLock, stdout, "/help\t\t\tPrints the server commands.\n");
	sfwrite(&printLock, stdout, "/shutdown\t\t\tShuts the server down.\n");
	sfwrite(&printLock, stdout, "\x1B[0m");
	fflush(stdout);
	sfwrite(&printLock, stdout, "\n");
}

ssize_t Recv(int sockfd, char buf[]){
	memset((char*)buf, 0, BUFFERSIZE);
	int i = 0;
	int space = 0, bsR1 = 0, bsN1 = 0, bsR2 = 0, bsN2 = 0;

	while(i != 1000 || !bsR1 || !bsN1 || !bsR2 || !bsN2){
		int x = recv(sockfd, buf+i, 1, 0);
		if(x==0) return 0;
		// printf("AFTERRECV: %s\n", &buf[i]);
		// sleep(1);
		if(((buf[i]) == '\r') && (bsN1 == 0) && (buf[i-1]) == ' '){
			space = 1;
			bsR1 = 1;
		}
		else if(((buf[i]) == '\r') && bsN1){
			bsR2 = 1;
		}
		else if(((buf[i]) == '\n') && bsR1 && (bsR2 == 0)){
			bsN1 = 1;
		}
		else if(((buf[i]) == '\n') && bsN1 && bsR1 && bsR2){
			bsN2 = 1;
		}
		else{
			space = 0;
			bsR1 = 0;
			bsR2 = 0;
			bsN1 = 0;
			bsN2 = 0;
		}
		if(bsN1 && bsN2 && bsR1 && bsR2 && space){
			//FOUND PROTOCOL
			return i+1;
		}
		i++;
	}
	return -1;
}

int sendClientRequest(char* output, int client_socket){
	if(verbose == 1){
		changeTextColor(VERBOSE);
		//fprintf(stderr, "SENDING: %s TO: %d\n", output, client_socket);
		sfwrite(&printLock, stdout, "SENDING: %s TO: %d\n", output, client_socket);
		changeTextColor(DEFAULT);
	}
	//printf("%zu\n", strlen(output));
	if((send(client_socket, output, strlen(output), 0)) == -1)
		return 0;
	else
		return 1;
}

void changeTextColor(char *colorName){
	
	if(!strcmp(colorName, DEFAULT))
		printf(DEFAULT_COLOR);
	else if(!strcmp(colorName, VERBOSE))
		printf(VERBOSE_COLOR);
	fflush(stdout);
}

void fillfd(){
	int max_sd = 0;
	int sd = 0;
	int i;
					
	FD_ZERO(&commfd);
	FD_SET(piped[0], &commfd);
	memset(&commClients[0], 0, MAX_CLIENTS);

	userNode_t* k = masterList->head;
	i = 0;
	while(k != NULL){
		commClients[i++] = k->fd;
		k = k->next;
	}
	for(i = 0; i < MAX_CLIENTS; i++){
		sd = commClients[i];
		if(sd > 0){
			fcntl(sd, F_SETFL, O_NONBLOCK);
			FD_SET(sd, &commfd);
		}
		if(sd > max_sd){
			max_sd = sd;
		}
	}
}

void sha256(char *password, char outputBuffer[65]){

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, password, strlen(password));
	SHA256_Final(hash, &sha256);

	int i = 0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}

void deleteClient(int client_socket){
	int found = 0;
	sendClientRequest(BYE_MSG, client_socket);
	userNode_t* j = masterList->head;
		while(j != NULL){
			if(j->fd == client_socket){
				found = 1;
				break;
			}
			j = j->next;
		}
		if(found == 1){
			pthread_mutex_lock(&R_lock);
			userListDeleteUser(masterList, j);
			pthread_mutex_unlock(&R_lock);
		}

	close(client_socket);
}
