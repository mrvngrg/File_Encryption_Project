#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../../server_headers/serverThread.h"

void *handle_receive_message(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);

    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int n = read(client_socket, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            printf("client disconnected\n");
            break;
        }
        printf("received: %s\n", buffer);
    }
    return NULL;
}