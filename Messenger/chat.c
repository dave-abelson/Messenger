//chat program
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/file.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include "sfwrite.c"

#define MAX_INPUT 1024
#define ERROR "ERROR"
#define PROMPT_COLOR "\x1B[1;36m"
#define TEXT_COLOR "\x1B[0m"
#define ERROR_COLOR "\x1B[1;31m"
#define SEND_PROMPT ">"
#define RECEIVE_PROMPT "<"

#define createDateTimeStamp(theTime){ \
	memset(theTime, '\0', 20); \
	time_t tmp = time(NULL); \
	struct tm* t = localtime(&tmp); \
	strftime(theTime, 20, "%m/%d/%y-%I:%M%P", t); \
}

void changeTextColor(char* colorName);
void printSend();
void printReceive();
ssize_t Recv(int sockfd, char buf[]);
ssize_t Send(int sockfd, const char* buf, size_t len);
void auditCmd(char* name, char* thecommand, char* fOrS, char* fd);

int main(int argc, char** argv){
	if(argc < 2){
		printf("NOT ENOUGH ARGUMENTS!\n");
		exit(1);
	}
	fd_set fdset, ready_set;
	FD_ZERO(&fdset);
	FD_SET(0, &fdset);
	int clientfd = atoi(argv[1]);
	FD_SET(clientfd, &fdset);
	char received[MAX_INPUT];
	while(1){
		memset(received, '\0', MAX_INPUT);
		FD_ZERO(&ready_set);
		ready_set = fdset;
		select(clientfd+1, &ready_set, NULL, NULL, NULL);
		if(FD_ISSET(0, &ready_set)){
			// printSend();
			char *cursor;
			char last_char;
			int count, rv;
			char cmd[MAX_INPUT];
			memset(cmd, '\0', MAX_INPUT);
			for(rv = 1, count = 0, cursor = cmd, last_char = 1; rv && (++count < (MAX_INPUT - 1)) 
				&& (last_char != '\n'); cursor++){
				rv = read(0, cursor, 1);
				last_char = *cursor;
				// if(last_char == 3){
				// 	write(1, "^c", 2);
				// }
			}
			// *cursor = '\0';
			if(!strcmp(cmd, "/close\n")){
				auditCmd(argv[3], "/close", "success", argv[2]);
				exit(0);
			}
			// else if(!strncmp(cmd, "/", 1) && (strlen(cmd)-1 != 2)){
			// 	char temp[MAX_INPUT];
	  //   		memset(temp, '\0', MAX_INPUT);
	  //   		strncpy(temp, cmd, strlen(cmd)-1);
	  //   		auditCmd(argv[2], temp, "failure", argv[1]);
			// }
			/* otherwise, send the message to client to send to server 
			   to send to other client to send to otehr chat */
			Send(clientfd, cmd, strlen(cmd));
		}
		if(FD_ISSET(clientfd, &ready_set)){
			// printReceive();
			int x;
			x = Recv(clientfd, received);
			if(x == 0){
				write(1, "Other user has logged off.\n", 27);
				write(1, "Press Enter to exit:", 20);
				getchar();
				exit(0);
			}else{
				if(received[0] == '\0'){
					write(1, "Other user has logged off.\n", 27);
					write(1, "Press Enter to exit:", 20);
					getchar();
					exit(0);
				}
				else{
					printf("%s", received);
					fflush(stdout);
				}
			}
		}
	}
}

void changeTextColor(char* colorName){
	if(!strcmp(colorName, PROMPT_COLOR))
		printf(PROMPT_COLOR);
	else if(!strcmp(colorName, TEXT_COLOR))
		printf(TEXT_COLOR);
	else if(!strcmp(colorName, ERROR))
		printf(ERROR_COLOR);
	fflush(stdout);
}

void printSend(){
	changeTextColor(PROMPT_COLOR);
	printf(SEND_PROMPT);
	fflush(stdout);
	changeTextColor(TEXT_COLOR);
}

void printReceive(){
	changeTextColor(PROMPT_COLOR);
	printf(RECEIVE_PROMPT);
	fflush(stdout);
	changeTextColor(TEXT_COLOR);
}

ssize_t Recv(int sockfd, char buf[]){
	int i = 0;
	int x = recv(sockfd, buf+i, 1, 0);
	if(x == 0){
		return 0;
	}
	i++;
	while(i != 1024){
		recv(sockfd, buf+i, 1, 0);
		if(buf[i] == '\n'){
			return i;
		}
		i++;
	}
	return -1;
}

/* returns amount of bytes sent on success, -1 on failure */
ssize_t Send(int sockfd, const char* buf, size_t len){
	int sentAll = 0, amtSent = 0;
	while(!sentAll){
		amtSent = send(sockfd, buf, len-amtSent, 0);
		if(amtSent == len){
			// send(sockfd, "\n", 1, 0);
			return amtSent;
		}
	}
	// send(sockfd, "\n", 1, 0);
	return -1;
}

void auditCmd(char* name, char* thecommand, char* fOrS, char* fd){
	char temp[MAX_INPUT];
	char theTime[20];
	createDateTimeStamp(theTime);
	memset(temp, '\0', MAX_INPUT);
	sprintf(temp, "%s, %s, CMD, %s, %s, %s\n", theTime, name, thecommand, fOrS, "chat");
	int thefd = atoi(fd);
	flock(thefd, LOCK_EX);
	write(thefd, temp, strlen(temp));
	flock(thefd, LOCK_UN);
}