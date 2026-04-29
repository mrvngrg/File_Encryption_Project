# To run, enter: make all
all: encryption

encryption: src/encryption/main.c src/encryption/queue.c src/encryption/thread.c src/encryption/globals.c src/encryption/encryption.c src/client/client.c
	gcc src/encryption/main.c src/encryption/queue.c src/encryption/thread.c src/encryption/globals.c src/encryption/encryption.c src/client/client.c -o encryption -lssl -lcrypto

server: src/server/server.c src/server/server_global.c src/server/serverThread.c src/server/socket_queue.c
	gcc src/server/server.c src/server/server_global.c src/server/serverThread.c src/server/socket_queue.c -o server
	
monitor: src/security/monitor_component.c
	gcc src/security/monitor_component.c -o monitor