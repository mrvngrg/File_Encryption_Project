#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080

int main() {
    int status;
    int valread;
    int client_fd;

    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
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
    char* hey = "hey";
    send(client_fd, hey, strlen(hey), 0);
    printf("send hey\n");
    valread = read(client_fd, buffer, 1024 -1);

    close (client_fd);
    return 0;
}
