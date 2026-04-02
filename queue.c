#include "headers/queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void initializeQueue(Queue *q) {
    q->head = NULL;
    q->tail = NULL;
}

void enqueue(Queue *q, const char *path) {
    Node *newNode = malloc(sizeof(Node));
    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    newNode->data = strdup(path);
    if (newNode->data == NULL) {
        free(newNode);
        printf("Memory allocation failed\n");
        return;
    }

    newNode->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = newNode;
        return;
    }

    q->tail->next = newNode;
    q->tail = newNode;
}

char *dequeue(Queue *q) {
    if (q->head == NULL) {
        return NULL;
    }

    Node *temp = q->head;
    char *data = temp->data;

    q->head = q->head->next;

    if (q->head == NULL) {
        q->tail = NULL;
    }

    free(temp);
    return data;
}

char *get_element(Queue *q) {
    if (q->head == NULL) {
        return NULL;
    }
    return q->head->data;
}