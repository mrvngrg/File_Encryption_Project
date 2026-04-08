#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080

struct sockaddr_in address;
socklen_t addrlen = sizeof(address);

void *connection_listener(int serverfd) {
    while (true) {
        listen(serverfd, 3);
        int new_socket = accept(serverfd, (struct sockaddr*) &address, &addrlen);
        if (new_socket == 0) {
            printf("client is connected");
        }      
    }
}

void *receive() {
    recv( sockfd, *buf, len, flags);
}



int main(int argc, char *argv) {
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    bind(serverfd, (struct sockaddr*)&address, addrlen);
    //setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    
    //should have a queue that stores ID's
    //should start thread that listen to new client and thread that listen to new informations about already connected sockets
} 