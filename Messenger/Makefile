CFLAGS = -g -Wall -Werror -pthread -lpthread -lssl -lcrypto
LOGFLAGS = -g -Wall -Werror -lncurses -lmenu

all: clean server client chat logEditor

server:
	gcc server.c -o server $(CFLAGS)
client:
	gcc client.c -o client $(CFLAGS) 
chat:
	gcc chat.c -o chat $(CFLAGS)
logEditor:
	gcc logEditor.c -o logEditor $(LOGFLAGS)

clean:
	rm -f *~ *.o server client chat logEditor

.PHONY: all