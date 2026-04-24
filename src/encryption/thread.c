#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "../../headers/thread.h"
#include "../../headers/encryption.h"
#include "../../headers/globals.h"

unsigned char key[16] = "qwertyuiopasdfgh";

void start_encrypt() {
    while (true) {
        char *head = peek(&queue); //race condition maybe peek_and_dequeue.
        if (head == NULL || strcmp(head, "END_ENCRYPT") == 0) break;
        
        char *data = dequeue(&queue);
        printf("TID: %lu: \n%s\n", (unsigned long)pthread_self(), data);
        char *filename = encrypt_file(data, key);
        enqueue(&queue, filename);
        free(data);
        free(filename);
    }
}

void start_decrypt() {
    while (true) {
        char *head = peek(&queue);
        if (head == NULL || strcmp(head, "END_DECRYPT") == 0) break;

        char *data = dequeue(&queue);
        printf("TID: %lu: \n%s\n", (unsigned long)pthread_self(), data);
        char *filename = decrypt_file(data, key);
        enqueue(&queue, filename);
        free(data);
        free(filename);
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
