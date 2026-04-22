#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include "headers/thread.h"
#include "headers/encryption.h"
#include "headers/globals.h"
#include <time.h>

unsigned char key[16] = "qwertyuiopasdfgh";

void start_encrypt() {
    while (encrypt_queue.tail != NULL) { //I'm not sure about this
        char *data = dequeue(&encrypt_queue);
        printf("TID: %lu: %s\n", (unsigned long)pthread_self(), data);
        encrypt_file(data, key);
        free(data);
    }
}

void start_decrypt() {
    while (decrypt_queue.tail != NULL) { //I'm not sure about this
        char *data = dequeue(&decrypt_queue);
        printf("TID: %lu: \n%s\n", (unsigned long)pthread_self(), data);
        decrypt_file(data, key);
        free(data);
    }
}

void *runner(void *arg) {
    if (*(bool *)arg == true) {
        start_encrypt();
    } else {
        start_decrypt();
    }
    return NULL;
}

void initialize_threads(int n, bool encrypt) {

    pthread_t tids[n];
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    bool* encrypt_ptr = malloc(sizeof(bool));
    if (!encrypt_ptr) {
        return;
    }
    *encrypt_ptr = encrypt;

    for (int i = 0; i < n; i++) {
        pthread_create(&tids[i], &attr, runner, encrypt_ptr);
    }

    for (int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }

}
