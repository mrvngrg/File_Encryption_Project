#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "server_headers/serverThread.h"
#include "server_headers/server_global.h"

#define PORT 8080

struct sockaddr_in address;
socklen_t addrlen = sizeof(address);

void get_list() {
    Node *curr = socket_queue.head;
        while (curr != NULL) {
            printf("socket_id : %d\n",curr->socketfd);
            curr = curr->next;
        }
}

void *connection_listener(void *arg) {
    int server_socket = *(int *)arg;
    free(arg);

    while (true) {
        printf("waiting for connection\n");
        int new_socket = accept(server_socket, (struct sockaddr*) &address, &addrlen);
        if (new_socket >= 0) {
            printf("client connected: %d\n", new_socket);
            enqueue(&socket_queue, new_socket);

            int *client_socket = malloc(sizeof(int));
            *client_socket = new_socket;

            pthread_t msg_thread;
            pthread_create(&msg_thread, NULL, handle_receive_message, client_socket);//one thread per client
            pthread_detach(msg_thread);
        } else {
            perror("accept");
        }
    }
    return NULL;
}

void *commands_listener(void *arg) {
    char command[1024];
    while (true) {
        fgets(command, sizeof(command), stdin);

        char *arguments[10];
        int i = 0;

        char *token = strtok(command, ";");

        while (token != NULL) {
            arguments[i] = token;
            i++;

            token = strtok(NULL, ";");
        }

        if (strcmp(arguments[0], "list") == 0) {
            get_list();
        } else {
            pthread_mutex_lock(&socket_queue.lock);
            Node *curr = socket_queue.head;
            while (curr != NULL) {
                send(curr->socketfd, command, strlen(command), 0);
                curr = curr->next;
            }
            pthread_mutex_unlock(&socket_queue.lock);
        }
    } 
}

int main(int argc, char const* argv[]) {
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        perror("socket");
        return 1;
    }

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

    initializeQueue(&socket_queue);

    int *server_socket = malloc(sizeof(int));
    *server_socket = serverfd;

    pthread_t connection_tid, command_tid;

    pthread_create(&connection_tid, NULL, connection_listener, server_socket);
    pthread_create(&command_tid, NULL, commands_listener, NULL);

    pthread_join(connection_tid, NULL);
    pthread_join(command_tid, NULL);

    close(serverfd);
    return 0;   
}