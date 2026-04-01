#include "queue.h"
#include <stdio.h>
#include <stdlib.h>

void initializeQueue(Queue *q) {
    q->head = NULL;
    q->tail = NULL;
}

void enqueue(Queue* q, char *path) {
    Node* newNode = malloc(sizeof(Node));

    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    newNode->data = path;
    newNode->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = newNode;
        return;
    }

    q->tail->next = newNode;
    q->tail = newNode;
}

char *dequeue(Queue *q) {
    if (q -> head == NULL) {
        printf("queue is already empty");
    } 

    Node *temp = q->head;
    char *data = temp->data;

    q->head = q->head->next;

    if (q->head == NULL) {
        q->tail = NULL;
    }
    free(temp);
}