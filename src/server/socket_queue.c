#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../server_headers/socket_queue.h"

void initializeQueue(Queue *q) {
    q->head = NULL;
    q->tail = NULL;
    pthread_mutex_init(&q->lock, NULL);
}

void enqueue(Queue *q, int socket) {
    pthread_mutex_lock(&q->lock);

    Node *newNode = malloc(sizeof(Node));
    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        pthread_mutex_unlock(&q->lock);
        return;
    }

    newNode->socketfd = socket;
    newNode->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = newNode;
    } else {
        q->tail->next = newNode;
        q->tail = newNode;
    }

    pthread_mutex_unlock(&q->lock);
}

int dequeue(Queue *q) {
    if (q->head == NULL) {
        return -1;
    }

    Node *temp = q->head;
    int data = temp->socketfd;

    q->head = q->head->next;

    if (q->head == NULL) {
        q->tail = NULL;
    }

    free(temp);
    return data;
}