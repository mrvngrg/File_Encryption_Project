# To run, enter: make all
all: encryption

encryption: 
	gcc main.c queue.c thread.c globals.c encryption.c -o encryption -lssl -lcrypto

server: 
	gcc server.c server_global.c serverThread.c socket_queue.c -o server

client: 
	gcc client.c -o client
