#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "../../headers/thread.h"
#include "../../headers/encryption.h"
#include "../../headers/globals.h"

void start_encrypt() {
    while (true) {

        char *data = peek_and_dequeue(&queue, "END_ENCRYPT");
        if (data == NULL){
            break;
        }
          
        /*
        if (strstr(data, ".locked") != NULL) {
            free(data);
            continue;
        }*/

        printf("TID: %lu: \n%s\n", (unsigned long)pthread_self(), data);
        unsigned char key[16];
        use_key(key);
        char *filename = encrypt_file(data, key);
        wipe_key(key);
        if (filename != NULL) {
            enqueue(&queue, filename);
            free(filename);
        }
        free(data);
    }
}

void start_decrypt() {
    while (true) {
        char *data = peek_and_dequeue(&queue, "END_DECRYPT");

        if (data == NULL){
            break;
        }

        printf("TID: %lu: \n%s\n", (unsigned long)pthread_self(), data);
        unsigned char key[16];
        use_key(key);
        char *filename = decrypt_file(data, key);
        wipe_key(key);
        if (filename != NULL) {
            enqueue(&queue, filename);
            free(filename);
        }
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

    if (encrypt) {
        remove_by_value(&queue, "END_DECRYPT");
        remove_by_value(&queue, "END_ENCRYPT");
        enqueue(&queue, "END_ENCRYPT");
    } else {
        remove_by_value(&queue, "END_ENCRYPT");
        remove_by_value(&queue, "END_DECRYPT");
        enqueue(&queue, "END_DECRYPT");
    }

    //print_queue(&queue);

    bool* encrypt_ptr = malloc(sizeof(bool));
    if (!encrypt_ptr) {
        return;
    }
    *encrypt_ptr = encrypt;

    for (int i = 0; i < n; i++) {
        int tid = pthread_create(&tids[i], &attr, runner, encrypt_ptr);
        if (tid < 0) {
            printf("error by creating a thread\n");
        }
    }

    for (int i = 0; i < n; i++) {
        pthread_join(tids[i], NULL);
    }
}