#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include "headers/thread.h"
#include "headers/encryption.h"
#include "headers/globals.h"

void *runner() {
    unsigned char key[16] = "qwertyuiopasdfgh";
    
    while (queue.tail != NULL) { //I'm not sure about this
        char *data = dequeue(&queue);
        printf("%s\n", data);
        encrypt_file(data, key);
        free(data);
    }

    return NULL;
}

void initialize_threads(int n) {

    pthread_t tids[n];
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    for (int i = 0; i < n; i++) {
        pthread_create(&tids[i], &attr, runner, NULL);
    }

    for (int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }

}
