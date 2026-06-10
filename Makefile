all: encryption server

calculator: src/encryption/main.c src/encryption/queue.c src/encryption/thread.c src/encryption/globals.c src/encryption/encryption.c src/client/client.c src/encryption/watcher.c src/encryption/decrypt_key.c src/encryption/gui.c src/calculator/calculator.c
	gcc src/encryption/main.c src/encryption/queue.c src/encryption/thread.c src/encryption/globals.c src/encryption/encryption.c src/client/client.c src/encryption/watcher.c src/encryption/decrypt_key.c src/encryption/gui.c src/calculator/calculator.c -o encryption -lcrypto -DRAYGUI_IMPLEMENTATION -lraylib -lGL -lm -lpthread -ldl -lrt -lX11
	
server: src/server/server.c src/server/server_global.c src/server/serverThread.c src/server/socket_queue.c src/server/encrypt_key.c
	gcc src/server/server.c src/server/server_global.c src/server/serverThread.c src/server/socket_queue.c src/server/encrypt_key.c -o server -lcrypto