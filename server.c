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

void *message_listener(void *arg) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int n = read(server.new_socket, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            printf("client disconnected\n");
            break;
        }
        printf("received: %s\n", buffer);
    }
    return NULL;
}

void *connection_listener(void *arg) {
    while (true) {
        printf("waiting for connection\n");
        int new_socket = accept(server.serverfd, (struct sockaddr*) &address, &addrlen);
        if (new_socket >= 0) {
            printf("client connected\n");
            server.new_socket = new_socket;

            pthread_t msg_thread;
            pthread_create(&msg_thread, NULL, message_listener, NULL);
            pthread_detach(msg_thread);
        } else {
            perror("accept");
        }
    }
    return NULL;
}

int main() {
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        perror("socket");
        return 1;
    }
    server.serverfd = serverfd;

    int opt = 1;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(serverfd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(serverfd, 3) < 0) {
        perror("listen");
        return 1;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, connection_listener, NULL);
    pthread_join(tid, NULL);

    close(serverfd);
    return 0;
}