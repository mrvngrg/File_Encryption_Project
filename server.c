#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#define PORT 8080

struct server {
    int serverfd;
    int new_socket;
} server;

struct sockaddr_in address;
socklen_t addrlen = sizeof(address);

void *connection_listener() {
    while (true) {
        listen(server.serverfd, 3);
        printf("listen\n");
        int new_socket = accept(server.serverfd, (struct sockaddr*) &address, &addrlen);
        printf("test");
        if (new_socket == 0) {
            printf("client is connected\n");
            server.new_socket = new_socket;
        }      
    }
}

void *message_listener() {
    char buffer[1024] = { 0 };
    while (true) {
        read(server.new_socket, buffer, 1024 - 1);
        printf("%s\n", buffer);
    }
}

int main() {

    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    server.serverfd = serverfd;
    int opt = 1;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(serverfd, (struct sockaddr*)&address, addrlen);
    //setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    pthread_t tids[1];
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    for (int i = 0; i < 2; i++) {
        pthread_create(&tids[i], &attr, connection_listener, NULL);
    }

    for (int i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    
    //should have a queue that stores ID's
    //should start thread that listen to new client and thread that listen to new informations about already connected sockets
} 