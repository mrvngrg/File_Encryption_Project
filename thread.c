#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include "headers/thread.h"
#include "headers/encryption.h"
#include "headers/globals.h"

void *runner(void *arg) {
    unsigned char key[16] = "qwertyuiopasdfgh";
    
    while (1) {
        char *data = dequeue(&queue);
        if (data == NULL) {
            break;
        }

        printf("Processing: %s\n", data);
        decrypt_file(data, key);
        free(data);
    }

    return NULL;
}

void initialize_threads(int n) {
    if (n <= 0) {
        fprintf(stderr, "Invalid thread count\n");
        return;
    }

    pthread_t tids[n];
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    bool created[n];

    for (int i = 0; i < n; i++) {
        created[i] = false;
        int create = pthread_create(&tids[i], &attr, runner, NULL);
        if (create != 0) {
            fprintf(stderr, "error\n");
        } else {
            created[i] = true;
        }
    }

    for (int i = 0; i < n; i++) {
        if (created[i]) {
            pthread_join(tids[i], NULL);
        }
    }
}
