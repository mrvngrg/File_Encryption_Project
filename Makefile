# To run, enter: make all
all: encryption

encryption: main.c queue.c thread.c globals.c encryption.c
	gcc main.c queue.c thread.c globals.c encryption.c -o encryption -lssl -lcrypto

server: server.c server_global.c serverThread.c socket_queue.c
	gcc server.c server_global.c serverThread.c socket_queue.c -o server

client: client.c
	gcc client.c -o client
