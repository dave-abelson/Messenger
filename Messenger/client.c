//client program
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include "sfwrite.c"

#define _GNU_SOURCE
#define MAX_INPUT 1024
#define MAX_ARG 256

#define DEFAULT "DEFAULT"
#define VERBOSE "VERBOSE"
#define ERROR "ERROR"
#define CHAT "CHAT"
#define DEFAULT_COLOR "\x1B[0m"
#define VERBOSE_COLOR "\x1B[1;34m"
#define ERROR_COLOR "\x1B[1;31m"
#define CHAT_COLOR "\x1B[1;36m"

#define CLIENT_PROMPT "Messenger Client: "
#define WOLFIE_MSG "WOLFIE \r\n\r\n"
#define EIFLOW_MSG "EIFLOW\0"
#define IAM_MSG "IAM "
#define IAMNEW_MSG "IAMNEW "
#define NEWPASS_MSG "NEWPASS "
#define OLDPASS_MSG "PASS "
#define SSAPWEN_MSG "SSAPWEN"
#define TIME_MSG "TIME \r\n\r\n"
#define BYE_MSG "BYE \r\n\r\n"
#define LISTU_MSG "LISTU \r\n\r\n"
#define MSG_MSG "MSG "
#define INVALID_PROTOCOL_MSG "INVALID PROTOCOL"
#define NEW_PWD_PROMPT "Please enter a new password: "
#define EXIST_PWD_PROMPT "Please enter your password: "

#define createDateTimeStamp(theTime){ \
	memset(theTime, '\0', 20); \
	time_t tmp = time(NULL); \
	struct tm* t = localtime(&tmp); \
	strftime(theTime, 20, "%m/%d/%y-%I:%M%P", t); \
}

typedef struct userNode{ //sizeof struct is 56 bytes. :^)
	char name[32];
	int fd;
	pid_t pid;
	int chatTerminated;
	struct userNode *next;
	struct userNode *prev; 
}userNode_t;

typedef struct userList{
	userNode_t *head;
	userNode_t *tail;
	unsigned int size; //number of users connected
	int maxFd;
}userList_t;

userList_t* friendsList;
int clientfd;
fd_set fdset, ready_set;
char received[MAX_INPUT];
char chatReceived[MAX_INPUT];
int verboseTag;
pthread_mutex_t printLock;
int gotUOFF, gotMotd;
FILE* auditLog;
int auditLogFd;
char* auditLogName;
char* myName;

void printHelpMenu();
void printClientHelpMenu();
int open_clientfd(char *hostname, char *port);
void changeTextColor(char *colorName);
void sigint_handler(int sig);
void sigchld_handler(int sig);
int sendServerRequest(char* protocol);
void printPrompt();
void doNothing();
void itoa(int value, char *stringStore);
ssize_t recvChat(int sockfd, char buf[]);
ssize_t Recv(int sockfd, char buf[]);
ssize_t Send(int sockfd, const char* buf, size_t len);
void invalidFlags();
userList_t* initUserList();
userNode_t* userListAppend(userList_t* ul, char userName[], int userFd, pid_t pid);
int userListDelete(userList_t* ul, char userName[], int userFd);
int clearUserList(userList_t* ul);
userNode_t* findUser(userList_t* ul, char userName[]);
userNode_t* findUserFd(userList_t* ul, int userFd);
userNode_t* findUserPid(userList_t* ul, pid_t pid);
userNode_t* findMaxFd(userList_t* ul);
int updateMaxFd(userList_t* ul);
int exists(char* path);
void auditLogin(char* name, char* ip, char* port, char* fOrS, char* errOrMotd);
void auditCmd(char* name, char* thecommand, char* fOrS);
void auditMsg(char* name, char* toOrFrom, char* user, char* message);
void auditErr(char* name, char* errMsg);
void auditLogout(char* name, char* intOrErr);
void printLog();

int main(int argc, char **argv){
	pthread_mutex_init(&printLock, NULL);
	int createNewUser = 0, firstRun = 1, didMalloc = 0, aFlag = 0;
	int indexName, indexIP, indexPort;
	verboseTag = 0, gotMotd = 0;
	(void)firstRun; /* TEMP NOT SURE IF I SHOULD USE LATER */
	char* parsePtr;
	friendsList = initUserList();

	if(signal(SIGINT, sigint_handler) == SIG_ERR)
		exit(1);
	if(signal(SIGCHLD, sigchld_handler) == SIG_ERR)
		exit(1);
	signal(SIGPIPE, SIG_IGN);
	int opt, totalNumFlags = 1;
	while((opt = getopt(argc, argv, "hcva:")) != -1){
		switch(opt){
			case 'h':
				printClientHelpMenu();
				return EXIT_SUCCESS;
			case 'c':
				createNewUser = 1;
				totalNumFlags++;
				break;
			case 'v':
				verboseTag = 1;
				totalNumFlags++;
				break;
			case 'a':
				auditLogName = optarg;
				aFlag = 1;
				totalNumFlags+=2;
				break;
			default: /* invalid flag */
				printClientHelpMenu();
				sfwrite(&printLock, stdout, "Invalid flag passed!\n");
				return EXIT_FAILURE;
		}
	}
	if(aFlag){
		auditLog = fopen(auditLogName, "a");
		if(auditLog == NULL)
			sfwrite(&printLock, stdout, "Failed to open/create file w/ a flag.\n");
	}else{
		auditLogName = "audit.log";
		auditLog = fopen("audit.log", "a");
		if(auditLog == NULL)
			sfwrite(&printLock, stdout, "Failed to open/create file w/o a flag.\n");
	}
	auditLogFd = fileno(auditLog);
	indexName = totalNumFlags;
	indexIP = totalNumFlags + 1;
	indexPort = totalNumFlags + 2;
	myName = argv[indexName];
	if(1){
		clientfd = open_clientfd(argv[indexIP], argv[indexPort]);
		FD_ZERO(&fdset);
		FD_SET(0, &fdset);
		FD_SET(clientfd, &fdset);
		// FD_ZERO(&ready_set);
		sfwrite(&printLock, stdout,"clientfd: %d\n", clientfd);
		if(clientfd == -1){
			auditErr(argv[indexName], "ERR 100 INVALID IP ADDRESS OR PORT");
			sfwrite(&printLock, stdout, "Invalid IP address / port number.\n");
			exit(1);
		}else{
			sendServerRequest(WOLFIE_MSG);
			if(verboseTag){
				changeTextColor(VERBOSE);
				sfwrite(&printLock, stdout, "WOLFIE\n");
				changeTextColor(DEFAULT);
			}
			Recv(clientfd, received);
			parsePtr = strstr(received, "\r\n\r\n");
			// char* temp = strchr(received, '\r');
			//if parse ptr is null then don't access it!
			if(parsePtr == NULL){
				printf("hehe\n");
				close(clientfd);
				return EXIT_FAILURE;
			}
			parsePtr[-1] = '\0';
			if(!strcmp(received, EIFLOW_MSG)){
				if(verboseTag){
					changeTextColor(VERBOSE);
					sfwrite(&printLock, stdout, "EIFLOW\n");
					changeTextColor(DEFAULT);
				}
			}else{
				changeTextColor(ERROR);
				sfwrite(&printLock, stdout, "ERR 100 EIFLOW NOT RECEIVED!\n");
				changeTextColor(DEFAULT);
				exit(1);
			}
			if(createNewUser){
				char tempName[strlen(IAMNEW_MSG) + strlen(argv[indexName]) + 5];
				memset(tempName, 0, sizeof(tempName));
				strncpy(tempName, (char*)IAMNEW_MSG, strlen(IAMNEW_MSG));
				strcat(tempName, argv[indexName]);
				if(verboseTag){
					changeTextColor(VERBOSE);
					sfwrite(&printLock, stdout, "%s\n", tempName);
					changeTextColor(DEFAULT);
				}
				strcat(tempName, " \r\n\r\n");
				sendServerRequest((char*)tempName);
			}else{
				char tempName[strlen(IAM_MSG) + strlen(argv[indexName]) + 5];
				memset(tempName, 0, sizeof(tempName));
				strncpy(tempName, (char*)IAM_MSG, strlen(IAM_MSG));
				strcat(tempName, argv[indexName]);
				if(verboseTag){
					changeTextColor(VERBOSE);
					sfwrite(&printLock, stdout, "%s\n", tempName);
					changeTextColor(DEFAULT);
				}
				strcat(tempName, " \r\n\r\n");
				sendServerRequest((char*)tempName);
			}
			while(1){
				ready_set = fdset;
				select(friendsList->maxFd+20, &ready_set, NULL, NULL, NULL);
				if(FD_ISSET(0, &ready_set)){
					// printPrompt();
					char *cursor;
					char last_char;
					int count, rv;
					char cmd[MAX_INPUT];
					for(rv = 1, count = 0, cursor = cmd, last_char = 1; rv && (++count < (MAX_INPUT-1)) 
						&& (last_char != '\n'); cursor++) { 
	      				rv = read(0, cursor, 1);
	      				last_char = *cursor;
	      				// if(last_char == 3) {
	        		// 		write(1, "^c", 2);
	      				// }
	    			}
	    			*cursor = '\0';
	    			if(!strcmp(cmd, "/time\n")){
	    				if((sendServerRequest(TIME_MSG)) == -1)
	    					sfwrite(&printLock, stdout, "Signal sending failure.\n");
	    				auditCmd(argv[indexName], "/time", "success");
	    			}else if(!strcmp(cmd, "/help\n")){
	    				printClientHelpMenu();
	    				auditCmd(argv[indexName], "/help", "success");
	    			}else if(!strcmp(cmd, "/listu\n")){
	    				if((sendServerRequest(LISTU_MSG)) == -1)
	    					sfwrite(&printLock, stdout, "Signal sending failure.\n");
	    				auditCmd(argv[indexName], "/listu", "success");
	    			}else if(!strcmp(cmd, "/logout\n")){
	    				if((sendServerRequest(BYE_MSG)) == -1)
	    					sfwrite(&printLock, stdout, "Signal sending failure.\n");
	    				auditCmd(argv[indexName], "/logout", "success");
	    			}else if(!strncmp(cmd, "/chat", 5)){
	    				auditCmd(argv[indexName], "/chat", "success");
	    				char *chatptr = strchr(cmd, ' ');
	    				chatptr++;
	    				char *chatptr2 = strchr(chatptr, ' ');
	    				chatptr2[0] = '\0';
	    				chatptr2++;
	    				char *chatptr3 = strchr(chatptr2, '\n');
	    				chatptr3[0] = '\0';
	    				// char *sigSend = malloc(MAX_INPUT);
	    				char sigSend[MAX_INPUT];
	    				memset(sigSend, 0, MAX_INPUT);
	    				strcpy(sigSend, MSG_MSG);
	    				// printf("sigSend: %s\n", sigSend);
	    				strcat(sigSend, chatptr);
	    				// printf("sigSend2: %s\n", sigSend);
	    				strcat(sigSend, " ");
	    				// printf("sigSend3: %s\n", sigSend);
	    				strcat(sigSend, argv[indexName]);
	    				// printf("sigSend4: %s\n", sigSend);
	    				strcat(sigSend, " ");
	    				// printf("sigSend5: %s\n", sigSend);
	    				strcat(sigSend, chatptr2);
	    				// printf("sigSend6: %s\n", sigSend);
	    				strcat(sigSend, " \r\n\r\n");
	    				// printf("sigSend7: %s\n", sigSend);
	    				// char *plz = strchr(sigSend, '\n'); WOWWWW I DID IT HERE ALREADY LOL
	    				// plz[0] = ' ';
	    				sendServerRequest(sigSend);
	    				// printf("%s\n", sigSend);
	    				// free(sigSend);
	    			}else if(!strcmp(cmd, "/audit\n")){
	    				auditCmd(argv[indexName], "/audit", "success");
	    				printLog();
	    			}else if(!strncmp(cmd, "/", 1) && (strlen(cmd) != 2)){
	    				char temp[MAX_INPUT];
	    				memset(temp, '\0', MAX_INPUT);
	    				strncpy(temp, cmd, strlen(cmd)-1);
	    				auditCmd(argv[indexName], temp, "failure");
	    			}
	    		}
	    		if(FD_ISSET(clientfd, &ready_set)){
	    			if(Recv(clientfd, received) == 0){
	    				//disconnect.
	    				if(verboseTag){
	    					changeTextColor(VERBOSE);
	    					sfwrite(&printLock, stdout, "BYE\n");
	    					changeTextColor(DEFAULT);
	    				}
	    				int x = clearUserList(friendsList);
	    				sfwrite(&printLock, stdout, "%d users cleared.\n", x);
	    				close(clientfd);
	    				// if(didMalloc){
		    			// 	for(int j = 0; j < MAX_INPUT; j++){
			    		// 		free(serverSig[j]);
				    	// 	}
			    		// }
			    		auditLogout(argv[indexName], "intentional");
			    		fclose(auditLog);
						close(auditLogFd);
	    				return EXIT_SUCCESS;
	    			}
	    			// printf("RECEIVED: %s\n", received);
	    			parsePtr = strstr(received, "\r\n\r\n");
	    			if(parsePtr != NULL){
	    				parsePtr[-1] = '\0';
	    				// char **serverSig = malloc(MAX_INPUT);
	    				char *serverSig[MAX_INPUT];
	    				for(int i = 0; i < MAX_INPUT; i++){
	    					serverSig[i] = calloc(1, MAX_INPUT);
	    					// memset(serverSig[i], 0, MAX_INPUT);
	    				}
	    				didMalloc = 1;
	    				char *atemp;
	    				int ctr = 0;
	    				for(atemp = strtok(received, " "); atemp; atemp = strtok(NULL, " ")){
	    					strcpy(serverSig[ctr], atemp);
	    					ctr++;
	    				}
	    				// free(atemp2);
	    				if(!strcmp(serverSig[0], "ERR")){
	    					if(!strcmp(serverSig[1], "00")){
	    						changeTextColor(ERROR);
	    						sfwrite(&printLock, stdout, "%s %s %s %s\n", serverSig[0], serverSig[1], serverSig[2], serverSig[3]);
	    						changeTextColor(DEFAULT);
	    						auditLogin(argv[indexName], argv[indexIP], argv[indexPort], "fail", "ERR 00 USERNAME TAKEN");
	    						// ERR USER TAKEN, WRITE TO AUDIT LOG
	    					}else if(!strcmp(serverSig[1], "01")){
	    						changeTextColor(ERROR);
	    						sfwrite(&printLock, stdout, "%s %s %s %s %s\n", serverSig[0], serverSig[1], serverSig[2], serverSig[3], serverSig[4]);
	    						changeTextColor(DEFAULT);
	    						if(gotMotd)
	    							auditErr(argv[indexName], "ERR 01 USER NOT AVAILABLE");
	    						else
	    							auditLogin(argv[indexName], argv[indexIP], argv[indexPort], "fail", "ERR 01 USER NOT AVAILABLE");
	    						// ERR USER DOESNT EXIST, WRITE TO AUDIT LOG
	    					}else if(!strcmp(serverSig[1], "02")){
	    						changeTextColor(ERROR);
	    						sfwrite(&printLock, stdout, "%s %s %s %s\n", serverSig[0], serverSig[1], serverSig[2], serverSig[3]);
	    						changeTextColor(DEFAULT);
	    						auditLogin(argv[indexName], argv[indexIP], argv[indexPort], "fail", "ERR 02 BAD PASSWORD");
	    						// ERR BAD PASSWORD, WRITE TO AUDIT LOG
	    					}
	    					if(gotMotd)
			    				continue;
	    					close(clientfd);
	    					if(didMalloc){
		    					for(int j = 0; j < MAX_INPUT; j++){
			    					free(serverSig[j]);
				    			}
			    			}
	    					return EXIT_FAILURE;
	    				}else if(!strcmp(serverSig[0], "EMIT")){
	    					int timeInSecs = atoi(serverSig[1]);
	    					int mins, hours, tLeft = timeInSecs;
	    					hours = tLeft / 3600;
	    					tLeft = tLeft % 3600;
	    					mins = tLeft / 60;
	    					tLeft = tLeft % 60;
	    					sfwrite(&printLock, stdout, "Connected for %d hour(s), %d minute(s), %d second(s).\n", hours, mins, tLeft);
	    				}else if(!strcmp(serverSig[0], "BYE")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "BYE\n");
	    						changeTextColor(DEFAULT);
	    					}
	    					int x = clearUserList(friendsList);
	    					sfwrite(&printLock, stdout, "%d users cleared.\n", x);
	    					close(clientfd);
	    					if(didMalloc){
		    					for(int j = 0; j < MAX_INPUT; j++){
			    					free(serverSig[j]);
				    			}
			    			}
			    			auditLogout(argv[indexName], "intentional");
			    			fclose(auditLog);
							close(auditLogFd);
	    					return EXIT_SUCCESS;
	    				}else if(!strcmp(serverSig[0], "UTSIL")){
	    					sfwrite(&printLock, stdout, "----------USERS ONLINE----------\n");
	    					int firstLoop = 1;
	    					int i = 1;
	    					do{
	    						if(!firstLoop){
	    							i+=2;
	    						}
	    						else{
	    							firstLoop = 0;
	    						}
	    						sfwrite(&printLock, stdout, "%s\n", serverSig[i]);
	    					}while(i+1 != ctr);
	    				}else if(!strcmp(serverSig[0], "MOTD")){
	    					changeTextColor(VERBOSE);
	    					char temp[MAX_INPUT];
	    					memset(temp, '\0', MAX_INPUT);
	    					int x = 1;
	    					while(1){
	    						if(x == (ctr)){
	    							break;
	    						}
	    						else{
	    							if(x == 1){
	    								strcpy(temp, serverSig[x]);
	    								strcat(temp, " ");
	    							}
	    							else{
	    								strcat(temp, serverSig[x]);
	    								strcat(temp, " ");
	    							}
	    							sfwrite(&printLock, stdout, "%s ", serverSig[x++]);
	    						}
	    					}
	    					sfwrite(&printLock, stdout, "\n");
	    					auditLogin(argv[indexName], argv[indexIP], argv[indexPort], "success", temp);
	    					changeTextColor(DEFAULT);
	    					gotMotd = 1;
	    				}else if(!strcmp(serverSig[0], "MSG")){ /* SADJALSDJASD */
	    					int pleaseProceed = 0;
	    					if(strcmp(serverSig[1], serverSig[2]) == 0){
	    						changeTextColor(ERROR);
	    						sfwrite(&printLock, stdout, "ERR 100 CAN'T CHAT YOURSELF!\n");
	    						changeTextColor(DEFAULT);
	    						auditErr(argv[indexName], "ERR 100 CAN'T CHAT YOURSELF");
	    						//ERR CANT CHAT YOURSELF, WRITE TO AUDIT
	    						continue;
	    					}
	    					if((strcmp(serverSig[1], argv[indexName]) == 0) && (strcmp(serverSig[2], argv[indexName])) != 0) 
	    						pleaseProceed = 1;
	    					else if((strcmp(serverSig[1], argv[indexName]) != 0) && (strcmp(serverSig[2], argv[indexName])) == 0)
	    						pleaseProceed = 1;
	    					if(pleaseProceed == 0){
	    						changeTextColor(ERROR);
	    						sfwrite(&printLock, stdout, "ERR 100 INVALID NAMES RECEIVED FROM SERVER\n");
	    						changeTextColor(DEFAULT);
	    						auditErr(argv[indexName], "ERR 100 INVALID NAMES RECEIVED FROM SERVER");
	    						//ERR YOUR NAME ISN'T IN THE MSG PROTOCOL, WRITE TO AUDIT
	    						continue;
	    					}
	    					int indexOfOtherName;
	    					if(strcmp(serverSig[1], argv[indexName]) == 0){
	    						indexOfOtherName = 2;
	    					}else if(strcmp(serverSig[2], argv[indexName]) == 0){
	    						indexOfOtherName = 1;
	    					}
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						int x = 0;
	    						while(x < ctr){
	    							if(x == (ctr-1))
	    								sfwrite(&printLock, stdout, "%s\n", serverSig[x++]);
	    							else if(x != ctr)
	    								sfwrite(&printLock, stdout, "%s ", serverSig[x++]);
	    						}
	    						changeTextColor(DEFAULT);
	    					}

	    					char temp[MAX_INPUT];
	    					memset(temp, '\0', MAX_INPUT);
	    					strcpy(temp, serverSig[3]);
	    					strcat(temp, " ");
	    					int y = 4;
	    					while(y < ctr){
	    						strcat(temp, serverSig[y++]);
	    						strcat(temp, " ");
	    					}
	    					if(indexOfOtherName == 1) //THE MSG IS TO THEM
	    						auditMsg(argv[indexName], "to", serverSig[indexOfOtherName], temp);
	    					else if(indexOfOtherName == 2) //THE MSG IS FROM THEM
	    						auditMsg(argv[indexName], "from", serverSig[indexOfOtherName], temp);

	    					userNode_t* ptr = findUser(friendsList, serverSig[indexOfOtherName]);
	    					// if(ptr != NULL)
	    					// 	printf("CT: %d\n", ptr->chatTerminated);

	    					if(ptr == NULL){ //CASE 3
	    						// printf("CASE 3\n");
	    						pid_t pid;
			    				int fd[2];
			    				if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1){
				    				changeTextColor(ERROR);
				    				sfwrite(&printLock, stdout, "Error creating socket pair.\n");
				    				changeTextColor(DEFAULT);
				    			}

			    				if((pid = fork()) == -1){
			    					sfwrite(&printLock, stdout, "fork failed\n");
			    					sfwrite(&printLock, stdout, "%d\n", errno);
			    				}

			    				if(pid == 0){
			    					// printf("FORK FOR KFORK FROFKR FORK FORK\n");
			    					close(fd[1]);
				    				// printf("fd[0]: %d\tfd[1]: %d\n", fd[0], fd[1]);
				    				char *params[15];
				    				params[0] = "xterm";
				    				params[1] = "-geometry";
				    				params[2] = "45x35+50";
				    				params[3] = "-T";
				    				params[4] = argv[indexName];
				    				params[5] = "-fa";
				    				params[6] = "Liberation Mono";
				    				params[7] = "-fs";
				    				params[8] = "10";
				    				params[9] = "-e";
				    				params[10] = "./chat";
				    				char temp1[5];
				    				memset(temp1, 0, 5);
				    				itoa(fd[0], (char*)temp1);
				    				char temp2[MAX_INPUT];
				    				memset(temp2, 0, MAX_INPUT);
				    				itoa(auditLogFd, (char*)temp2);
				    				// printf("the fd: %d\n", fd[0]);
				    				params[11] = temp1;
				    				params[12] = temp2;
				    				params[13] = argv[indexName];
				    				params[14] = NULL;
				    				// for(int j = 0; j < 8; j++){
				    				// 	if(j < 7)
				    				// 		printf("%s ", params[j]);
				    				// 	else
				    				// 		printf("%s\n", params[j]);
				    				// }
				    				execvp(params[0], params);
			    				}else{
			    					close(fd[0]);
			    					FD_SET(fd[1], &fdset);
			    					sfwrite(&printLock, stdout, "pid: %d\n", pid);
					    			ptr = userListAppend(friendsList, serverSig[indexOfOtherName], fd[1], pid);
					    			// printf("Name added to friend's list: %s\nFile descriptor of the friend: %d\nProcess id of child: %d\n", serverSig[1], fd[1], pid);

					    			char sigSend[MAX_INPUT];
					    			memset(sigSend, 0, MAX_INPUT);
		    						int x = 4;
		    						if(indexOfOtherName == 2){
			    						strcpy(sigSend, "\x1B[1;31m");
			    						strcat(sigSend, serverSig[2]);
			    						strcat(sigSend, ": ");
			    					}else if(indexOfOtherName == 1){
			    						strcpy(sigSend, "\x1B[1;34m");
			    						strcat(sigSend, serverSig[2]);
			    						strcat(sigSend, ": ");
			    					}
		    						changeTextColor(DEFAULT);
		    						strcat(sigSend, serverSig[3]);
		    						while(x < ctr){
		    							strcat(sigSend, " ");
		    							strcat(sigSend, serverSig[x++]);
		    						}
		    						strcat(sigSend, "\x1B[0m\n");
		    						// printf("MESSAGE CASE 3: %s\n", sigSend);
		    						send(ptr->fd, sigSend, strlen(sigSend), 0);
			    				}
	    					}else{ //CASE 1 AND 2
	    						if(ptr->chatTerminated == 1){ //SCREEN DOESNT EXIST, USER DOES THO. CASE 2, FORK PROCESS, SET NEWPID, SET NEW FD, LEAVE NAME.
	    							printf("CASE 2\n");
	    							pid_t pid;
	    							int fd[2];
	    							if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1){
					    				changeTextColor(ERROR);
					    				sfwrite(&printLock, stdout, "Error creating socket pair.\n");
					    				changeTextColor(DEFAULT);
					    			}

				    				if((pid = fork()) == -1){
				    					sfwrite(&printLock, stdout, "fork failed\n");
				    					sfwrite(&printLock, stdout, "%d\n", errno);
				    				}

				    				if(pid == 0){
				    					// printf("FORK FOR KFORK FROFKR FORK FORK\n");
				    					close(fd[1]);
					    				// printf("fd[0]: %d\tfd[1]: %d\n", fd[0], fd[1]);
					    				char *params[15];
					    				params[0] = "xterm";
					    				params[1] = "-geometry";
					    				params[2] = "45x35+50";
					    				params[3] = "-T";
					    				params[4] = argv[indexName];
					    				params[5] = "-fa";
					    				params[6] = "Liberation Mono";
					    				params[7] = "-fs";
					    				params[8] = "10";
					    				params[9] = "-e";
					    				params[10] = "./chat";
					    				char temp1[5];
					    				memset(temp1, 0, 5);
					    				itoa(fd[0], (char*)temp1);
					    				char temp2[MAX_INPUT];
				    					memset(temp2, 0, MAX_INPUT);
				    					itoa(auditLogFd, (char*)temp2);
				    					// printf("the fd: %d\n", fd[0]);
				    					params[11] = temp1;
				    					params[12] = temp2;
				    					params[13] = argv[indexName];
				    					params[14] = NULL;
					    				// for(int j = 0; j < 8; j++){
					    				// 	if(j < 7)
					    				// 		printf("%s ", params[j]);
					    				// 	else
					    				// 		printf("%s\n", params[j]);
					    				// }
					    				execvp(params[0], params);
				    				}else{
				    					close(fd[0]);
				    					FD_SET(fd[1], &fdset);
				    					ptr->chatTerminated = 0;
				    					ptr->pid = pid;
					    				ptr->fd = fd[1];
					    				int y = updateMaxFd(friendsList);
					    				if(y == 1)
					    					sfwrite(&printLock, stdout, "New max fd updated!\n");
					    				else if(y == 0)
					    					sfwrite(&printLock, stdout, "No update needed!\n");
					    				else if(y == -1)
					    					sfwrite(&printLock, stdout, "other shit fucked up bruh\n");
					    				/* LEAVE NAME! */

					    				char sigSend[MAX_INPUT];
					    				memset(sigSend, '\0', MAX_INPUT);
		    							int x = 4;
		    							if(indexOfOtherName == 2){
			    							strcpy(sigSend, "\x1B[1;31m");
			    							strcat(sigSend, serverSig[2]);
			    							strcat(sigSend, ": ");
			    						}else if(indexOfOtherName == 1){
			    							strcpy(sigSend, "\x1B[1;34m");
			    							strcat(sigSend, serverSig[2]);
			    							strcat(sigSend, ": ");
			    						}
			    						changeTextColor(DEFAULT);
		    							strcat(sigSend, serverSig[3]);
		    							while(x < ctr){
		    								strcat(sigSend, " ");
		    								strcat(sigSend, serverSig[x++]);
		    							}

		    							strcat(sigSend, "\x1B[0m\n");

		    							// printf("MESSAGE CASE 2: %s\n", sigSend);
		    							// printf("NULL WTFFFFFF %d\n", ptr->fd);
		    							send(ptr->fd, sigSend, strlen(sigSend), 0);
				    				}
	    						}else if(ptr->chatTerminated == 0){ //SCREEN DOES EXIST. CASE 1
	    							// printf("CASE 1\n");
	    							char sigSend[MAX_INPUT];
	    							int x = 4;
	    							if(indexOfOtherName == 2){
			    						strcpy(sigSend, "\x1B[1;31m");
			    						strcat(sigSend, serverSig[2]);
			    						strcat(sigSend, ": ");
			    					}else if(indexOfOtherName == 1){
			    						strcpy(sigSend, "\x1B[1;34m");
			    						strcat(sigSend, serverSig[2]);
			    						strcat(sigSend, ": ");
			    					}
		    						changeTextColor(DEFAULT);
	    							strcat(sigSend, serverSig[3]);
	    							while(x < ctr){
	    								strcat(sigSend, " ");
	    								strcat(sigSend, serverSig[x++]);
	    							}

	    							strcat(sigSend, "\x1B[0m\n");

	    							// printf("MESSAGE CASE 1: %s\n", sigSend);
	    							send(ptr->fd, sigSend, strlen(sigSend), 0);
	    						}
	    					}
	    				}else if(!strcmp(serverSig[0], "HI")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s %s\n", serverSig[0], serverSig[1]);
	    						changeTextColor(DEFAULT);
	    					}
	    				}else if(!strcmp(serverSig[0], "HINEW")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s %s\n", serverSig[0], serverSig[1]);
	    						changeTextColor(DEFAULT);
	    					}
	    					// write(1, PWD_PROMPT, strlen(PWD_PROMPT));
	    					char* pwd;
	    					pwd = getpass(NEW_PWD_PROMPT);
	    					char sendSig[MAX_INPUT];
	    					strcpy(sendSig, NEWPASS_MSG);
	    					strcat(sendSig, pwd);
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s\n", sendSig);
	    						changeTextColor(DEFAULT);
	    					}
	    					strcat(sendSig, " \r\n\r\n");
	    					// printf("protocol: %s\n", sendSig);
	    					sendServerRequest(sendSig);
	    				}else if(!strcmp(serverSig[0], "AUTH")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s %s\n", serverSig[0], serverSig[1]);
	    						changeTextColor(DEFAULT);
	    					}
	    					char* pwd;
	    					pwd = getpass(EXIST_PWD_PROMPT);
	    					char sendSig[MAX_INPUT];
	    					strcpy(sendSig, OLDPASS_MSG);
	    					strcat(sendSig, pwd);
	    					strcat(sendSig, " \r\n\r\n");
	    					// printf("Protocol: %s\n", sendSig);
	    					sendServerRequest(sendSig);
	    				}else if(!strcmp(serverSig[0], "SSAP")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s\n", serverSig[0]);
	    						changeTextColor(DEFAULT);
	    					}
	    				}else if(!strcmp(serverSig[0], "SSAPWEN")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s\n", serverSig[0]);
	    						changeTextColor(DEFAULT);
	    					}
	    				}else if(!strcmp(serverSig[0], "UOFF")){
	    					if(verboseTag){
	    						changeTextColor(VERBOSE);
	    						sfwrite(&printLock, stdout, "%s %s\n", serverSig[0], serverSig[1]);
	    						changeTextColor(DEFAULT);
	    					}
	    					userNode_t* temp = findUser(friendsList, serverSig[1]);
	    					if(temp == NULL){
	    						sfwrite(&printLock, stdout, "Not chatting with disconnected user.\n");
	    					}
	    					else{
	    						gotUOFF = 1;
	    						close(temp->fd);
	    						// userListDelete(friendsList, temp->name, temp->fd);
	    					}
	    				}else{
	    					changeTextColor(ERROR);
	    					sfwrite(&printLock, stdout, "\nERR 100 INVALID PROTOCOL RECEIVED\n");
	    					changeTextColor(DEFAULT);
	    					auditErr(argv[indexName], "ERR 100 INVALID PROTOCOL RECEIVED");
	    				}
	    				for(int j = 0; j < MAX_INPUT; j++){
	    					free(serverSig[j]);
	    				}
	    			}else{
	    				changeTextColor(ERROR);
	    				sfwrite(&printLock, stdout, INVALID_PROTOCOL_MSG);
	    				changeTextColor(DEFAULT);
	    			}
	    		}
	    		if(friendsList->head != NULL){
	    			userNode_t* cursor = friendsList->head;
	    			while(cursor != NULL){
	    				if(FD_ISSET(cursor->fd, &ready_set)){
	    					memset((char*)chatReceived, 0, MAX_INPUT);
	    					int x = recvChat(cursor->fd, chatReceived);
	    					// printf("hi");
	    					if(x == 1){ //only newline
	    						// printf("IS IT ONLY NEWLINE?\n");
	    						// if(chatReceived[0] == '\n'){
	    						// 	printf("IT WAS A FUCKIGN NEWLINE\n");
	    						// }
	    					}
	    					else if(x == -1){
	    						// sfwrite(&printLock, stdout, "\t\t\tChat screen closed!\n");
	    						printf("Chat screen closed!\n");
	    					}
	    					else{
	    						char sigSend[MAX_INPUT];
	    						strcpy(sigSend, MSG_MSG);
	    						strcat(sigSend, cursor->name);
	    						strcat(sigSend, " ");
	    						strcat(sigSend, argv[indexName]);
	    						strcat(sigSend, " ");
	    						strcat(sigSend, chatReceived);
	    						// printf("sigsend after chatreceived: %s\n", sigSend);
	    						strcat(sigSend, " \r\n\r\n");
	    						sendServerRequest(sigSend);
	    					}
	    				}
	    				cursor = cursor->next;
	    			}
	    		}
			}
		}
	}	
	return EXIT_SUCCESS;
}

void printClientHelpMenu(){
	sfwrite(&printLock, stdout, "\n");
	changeTextColor(CHAT);
	sfwrite(&printLock, stdout, "./client [-hcv] [-a FILE] NAME SERVER_IP SERVER_PORT\n");
	sfwrite(&printLock, stdout, "-a FILE\t\t\tPath to the audit log file.\n");
	sfwrite(&printLock, stdout, "-h\t\t\tDisplays this help menu, and returns EXIT_SUCCESS.\n");
	sfwrite(&printLock, stdout, "-c\t\t\tRequests to server to create a new user.\n");
	sfwrite(&printLock, stdout, "-v\t\t\tVerbose print all incoming and outgoing protocol verbs & content.\n");
	sfwrite(&printLock, stdout, "NAME\t\t\tThis is the username to display when chatting.\n");
	sfwrite(&printLock, stdout, "SERVER_IP\t\tThe IP Address of the server to connect to.\n");
	sfwrite(&printLock, stdout, "SERVER_PORT\t\tThe port to connect to.\n\n");
	changeTextColor(DEFAULT);
}

void printHelpMenu(){
	sfwrite(&printLock, stdout, "\n");
	changeTextColor(CHAT);
	sfwrite(&printLock, stdout, "\t\t\tClient Commands\n");
	sfwrite(&printLock, stdout, "-------------------------------------------------------------------------\n");
	sfwrite(&printLock, stdout, "/time\t\tPrints out how long the client has been connected for.\n");
	sfwrite(&printLock, stdout, "/help\t\tPrints out the help menu.\n");
	sfwrite(&printLock, stdout, "/logout\t\tDisconnects the user from the server.\n");
	sfwrite(&printLock, stdout, "/listu\t\tPrints out a list of users connected.\n\n");
	sfwrite(&printLock, stdout, "/audit\t\tDumps the contents of the audit.log file to the client terminal.\n");
	changeTextColor(DEFAULT);
}

int open_clientfd(char *hostname, char *port){
	int clientfd;
	struct addrinfo hints, *listp, *p;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (AI_NUMERICSERV | AI_ADDRCONFIG);
	getaddrinfo(hostname, port, &hints, &listp);
	for(p = listp; p; p = p->ai_next){
		if((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0){
			continue; //SOCKET FAILED TRY NEXT
		}
		if(connect(clientfd, p->ai_addr, p->ai_addrlen) != -1){
			break; //found  a good socket
		}
		close(clientfd);
	}
	freeaddrinfo(listp);
	if(!p)
		return -1;
	else
		return clientfd;
}

void changeTextColor(char *colorName){
	if(!strcmp(colorName, CHAT))
		printf(CHAT_COLOR);
	else if(!strcmp(colorName, DEFAULT))
		printf(DEFAULT_COLOR);
	else if(!strcmp(colorName, VERBOSE))
		printf(VERBOSE_COLOR);
	else if(!strcmp(colorName, ERROR))
		printf(ERROR_COLOR);
	fflush(stdout);
}

/* returns 0 on send failure, 1 on success. */
int sendServerRequest(char* protocol){
	if(send(clientfd, protocol, strlen(protocol), 0) == -1)
		return 0;
	else
		return 1;
}

void sigint_handler(int sig){
	//send signal BYE to server.
	sendServerRequest(BYE_MSG);
	if(verboseTag){
		changeTextColor(VERBOSE);
		sfwrite(&printLock, stdout, "BYE\n");
		changeTextColor(DEFAULT);
	}
	auditLogout(myName, "intentional");
	fclose(auditLog);
	close(auditLogFd);
	exit(0);
}

void sigchld_handler(int sig){
	sfwrite(&printLock, stdout, "I caught your child.\n");
	pid_t pid;
	pid = wait(NULL);
	userNode_t* ptr = findUserPid(friendsList, pid);
	// printf("pidhandler: %d\n", pid);
	ptr->chatTerminated = 1;
	FD_CLR(ptr->fd, &fdset);
	if(gotUOFF){
		gotUOFF = 0;
		if(ptr == NULL){
	    	sfwrite(&printLock, stdout, "Couldn't find user that disconnected.\n");
	    }
	    else{
	    	userListDelete(friendsList, ptr->name, ptr->fd);
	    }
	}
	sfwrite(&printLock, stdout, "Child with process ID %d reaped.\n", pid);
	return;
}

void printPrompt(){
	changeTextColor(CHAT);
	printf(CLIENT_PROMPT);
	fflush(stdout);
	changeTextColor(DEFAULT);
}

void doNothing(){
	return;
}

void itoa(int value, char *stringStore){
	char temp[16];
	char *tempPtr = temp;
	int num;
	unsigned v;

	int sign = (value < 0);
	if(sign)	/* make sure if value is pos or neg */
		v = -value;
	else
		v = (unsigned)value;

	while(v || tempPtr == temp){
		num = v % 10;
		v /= 10;
		if(num < 10)
			*tempPtr++ = num +'0';
		else
			*tempPtr++ = num + 'a' - 10;
	}

	if(sign)
		*stringStore++ = '-';

	while(tempPtr > temp)
		*stringStore++ = *--tempPtr;
}

ssize_t recvChat(int sockfd, char buf[]){
	memset((char*)buf, 0, MAX_INPUT);
	int i = 0;
	while(i != 1024){
		recv(sockfd, buf+i, 1, 0);
		// printf("tits: %c\n", buf[i]);
		if(buf[i] == '\n') //finished receiving
			return i+1;
		i++;
	}
	return -1;
}

ssize_t Recv(int sockfd, char buf[]){
	memset((char*)buf, 0, MAX_INPUT);
	int i = 0;
	int space = 0, bsR1 = 0, bsN1 = 0, bsR2 = 0, bsN2 = 0;
	while(i != 1024 || !bsR1 || !bsN1 || !bsR2 || !bsN2){
		int x = recv(sockfd, buf+i, 1, 0);
		if(x == 0)
			return 0;
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

ssize_t Send(int sockfd, const char* buf, size_t len){
	int sentAll = 0, amtSent = 0;
	while(sentAll){
		amtSent = send(sockfd, buf, len-amtSent, 0);
		if(amtSent == len)
			return amtSent;
	}
	return -1;
}

void invalidFlags(){
	changeTextColor(ERROR);
	sfwrite(&printLock, stdout, "ERR 100 INVALID FLAGS\n");
	changeTextColor(DEFAULT);
	exit(1);
}

userList_t* initUserList(){
	userList_t* ul = (userList_t*)malloc(sizeof(userList_t));
	if(ul == NULL){
		perror("No space on heap to allocate memory!");
		exit(EXIT_FAILURE);
	}
	ul->head = NULL;
	ul->tail = NULL;
	ul->maxFd = 3;
	ul->size = 0;
	return ul;
}

userNode_t* userListAppend(userList_t* ul, char userName[], int userFd, pid_t userPid){
	userNode_t* newUser = (userNode_t*)malloc(sizeof(userNode_t));
	if(newUser == NULL)
		return NULL;
	strcpy(newUser->name, userName);
	newUser->fd = userFd;
	newUser->pid = userPid;
	newUser->chatTerminated = 0;
	newUser->next = NULL;
	newUser->prev = NULL;
	if(ul->head == NULL){ //no nodes in list
		ul->head = newUser;
		ul->tail = newUser;
	}else if(ul->head != NULL){
		if(ul->head == ul->tail){ //if there is one node in list
			ul->head->next = newUser;
			ul->tail = newUser;
			newUser->prev = ul->head;
		}
		else if(ul->head != ul->tail){ //two or more nodes in list
			ul->tail->next = newUser;
			newUser->prev = ul->tail;
			ul->tail = newUser;
		}
	}
	if(ul->maxFd < userFd)
		ul->maxFd = userFd;
	ul->size++;
	return newUser;
}

/* return -1 on failure, 0 on success */
int userListDelete(userList_t* ul, char userName[], int userFd){
	userNode_t* n = findUserFd(ul, userFd);
	if(ul->head == NULL){
		return -1;
	}
	close(userFd);
	// FD_CLR(userFd, &fdset);
	//if user is tail
	if(n->next == NULL && n->prev != NULL){
		n->prev->next = NULL;
		ul->tail = n->prev;
		free(n);
	}
	//if user is head 
	else if(n->next != NULL && n->prev == NULL){
		n->next->prev = NULL;
		ul->head = n->next;
		free(n);
	}
	//head and tail of list
	else if(n->next == NULL && n->prev == NULL){
		ul->tail = NULL;
		ul->head = NULL;
		free(n);
	}
	//in the middle, no relation to head or tail
	else{
		n->prev->next = n->next;
		n->next->prev = n->prev;
		free(n);
	}
	sfwrite(&printLock, stdout, "ul maxfd is: %d, userfd is: %d\n", ul->maxFd, userFd);
	if(ul->maxFd == userFd){ //node to remove is the max. need to find new max.
		userNode_t* temp = findMaxFd(ul);
		if(temp == NULL){ //NO MORE NODES IN THE LIST
			ul->maxFd = 3;
		}else{ //WE FOUND NODE WITH NEW MAX
			ul->maxFd = temp->fd;
		}
	}
	ul->size--;
	return 0;
}
/* return # of users cleared */
int clearUserList(userList_t* ul){
	//if nothing is in the list
	if(ul->head == NULL){
		free(ul);
		return 0;
	}
	else{
		userNode_t *i = ul->head;
		userNode_t *temp;
		int x = 0;
		while(i != NULL){
			temp = i;
			i = i->next;
			free(temp);
			x++;
		}
		free(ul);
		return x;
	}
}

/* returns reference to node if found, NULL if not */
userNode_t* findUser(userList_t* ul, char userName[]){
	if(ul->head != NULL){
		userNode_t* cursor = ul->head;
		if(!strcmp(cursor->name, userName)) //head is the node we are looking for
			return cursor;
		if(cursor != ul->tail){ //head not the node, and more than 1 node in list
			while(cursor != ul->tail){ // while cursor.getNext() != tail
				if(!strcmp(cursor->name, userName))
					return cursor;
				cursor = cursor->next;
			}
		}
	}
	return NULL;
}

userNode_t* findUserFd(userList_t* ul, int userFd){
	if(ul->head != NULL){
		userNode_t* cursor = ul->head;
		if(cursor->fd == userFd) //head is the node we are looking for
			return cursor;
		if(cursor != ul->tail){ //head not the node, and more than 1 node in list
			while(cursor != ul->tail){ // while cursor.getNext() != tail
				if(cursor->fd == userFd)
					return cursor;
				cursor = cursor->next;
			}
		}
	}
	return NULL;
}

/* CHANGED WHILE(CURSOR->NEXT SHIT) */
userNode_t* findUserPid(userList_t* ul, pid_t pid){
	if(ul->head == NULL)
		sfwrite(&printLock, stdout, "rip\n");
	if(ul->head != NULL){
		userNode_t* cursor = ul->head;
		// printf("cursor pid: %d\n", cursor->pid);
		if(cursor->pid == pid) //head is the node we are looking for
			return cursor;
		if(cursor != ul->tail){ //head not the node, and more than 1 node in list
			while(cursor != ul->tail){ // while cursor.getNext() != tail
				// printf("a pid: %d\n", cursor->pid);
				if(cursor->pid == pid)
					return cursor;
				cursor = cursor->next;
			}
		}
	}
	return NULL;
}

userNode_t* findMaxFd(userList_t* ul){
	if(ul->head != NULL){
		userNode_t *cursor = ul->head;
		int temp = ul->maxFd;
		userNode_t *nodeWithMax = NULL;
		while(cursor != NULL){
			if(cursor->fd > temp)
				nodeWithMax = cursor;
			cursor = cursor->next;
		}
		return nodeWithMax;
	}else{
		return NULL; //LIST IS EMPTY.
	}
}

/* returns 1 if updated new max, 0 if not, -1 if findMaxFd returned NULL */
int updateMaxFd(userList_t* ul){
	userNode_t* temp = findMaxFd(ul);
	if(temp == NULL)
		return -1;
	if(temp->fd > ul->maxFd){
		ul->maxFd = temp->fd;
		return 1;
	}else{
		return 0;
	}
}

/* returns 1 if exists, 0 if not */
int exists(char* path){
	struct stat pStat;
	return (stat(path, &pStat) == 0);
}

void auditLogin(char* name, char* ip, char* port, char* fOrS, char* errOrMotd){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, LOGIN, %s:%s, %s, %s\n", theTime, name, ip, port, fOrS, errOrMotd);
	flock(auditLogFd, LOCK_EX);
	write(auditLogFd, temp, strlen(temp));
	flock(auditLogFd, LOCK_UN);
}

void auditCmd(char* name, char* thecommand, char* fOrS){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, CMD, %s, %s, %s\n", theTime, name, thecommand, fOrS, "client");
	flock(auditLogFd, LOCK_EX);
	write(auditLogFd, temp, strlen(temp));
	flock(auditLogFd, LOCK_UN);
}

void auditMsg(char* name, char* toOrFrom, char* user, char* message){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, MSG, %s, %s, %s\n", theTime, name, toOrFrom, user, message);
	flock(auditLogFd, LOCK_EX);
	write(auditLogFd, temp, strlen(temp));
	flock(auditLogFd, LOCK_UN);
}

void auditErr(char* name, char* errMsg){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, %s, %s\n", theTime, name, "ERR", errMsg);
	flock(auditLogFd, LOCK_EX);
	write(auditLogFd, temp, strlen(temp));
	flock(auditLogFd, LOCK_UN);
}

void auditLogout(char* name, char* intOrErr){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, %s, %s\n", theTime, name, "LOGOUT", intOrErr);
	flock(auditLogFd, LOCK_EX);
	write(auditLogFd, temp, strlen(temp));
	flock(auditLogFd, LOCK_UN);
}

void printLog(){
	FILE* stream = fopen(auditLogName, "r");
	int streamFd = fileno(stream);
	if(flock(streamFd, LOCK_EX) < 0){
		sfwrite(&printLock, stdout, "locking somehow failed?\n");
	}
	char buf[1];
	memset(buf, '\0', 1);
	while(read(streamFd, buf, 1) == 1)
		sfwrite(&printLock, stdout, buf);
	flock(streamFd, LOCK_UN);
}