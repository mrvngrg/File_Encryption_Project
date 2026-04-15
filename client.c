#include <stdbool.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#define PORT 8080

void *commands_listener(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[1024];

    while (true){
        int valread = read(client_fd, buffer, sizeof(buffer) -1);
        if (valread > 0 ) {
            buffer[valread] = '\0';
            printf("%s", buffer);
        }
    }
}

int main() {
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

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
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