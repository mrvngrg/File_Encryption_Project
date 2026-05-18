#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../../headers/queue.h"

void initializeQueue(Queue *q) {
    pthread_mutex_init(&q->lock, NULL);

    q->head = NULL;
    q->tail = NULL;
}

void enqueue(Queue *q, const char *path) {
    pthread_mutex_lock(&q->lock);

    Node *newNode = malloc(sizeof(Node));
    if (newNode == NULL) {
        printf("Memory allocation failed\n");
        pthread_mutex_unlock(&q->lock);
        return;
    }

    newNode->data = strdup(path);
    if (newNode->data == NULL) {
        free(newNode);
        printf("Memory allocation failed\n");
        pthread_mutex_unlock(&q->lock);
        return;
    }

    newNode->next = NULL;

    if (q->tail == NULL) {
        q->head = q->tail = newNode;
        pthread_mutex_unlock(&q->lock);
        return;
    }

    q->tail->next = newNode;
    q->tail = newNode;

    pthread_mutex_unlock(&q->lock);
}

char *dequeue(Queue *q) {

    pthread_mutex_lock(&q->lock);

    if (q->head == NULL) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }

    Node *temp = q->head;
    char *data = temp->data;

    q->head = q->head->next;

    if (q->head == NULL) {
        q->tail = NULL;
    }

    free(temp);
    pthread_mutex_unlock(&q->lock);
    return data;
}

char *get_element(Queue *q) {
    if (q->head == NULL) {
        return NULL;
    }
    return q->head->data;
}

void remove_by_value(Queue *q, const char *value) {

    pthread_mutex_lock(&q->lock);

    Node *curr = q->head;
    Node *prev = NULL;

    while (curr != NULL) {
        if (strcmp(curr->data, value) == 0) {
            if (prev == NULL) q->head = curr->next;
            else prev->next = curr->next;
            if (curr == q->tail) q->tail = prev;
            free(curr->data);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_mutex_unlock(&q->lock);

}

void print_queue(Queue *q) {
    if (q == NULL) {
        printf("Queue is NULL\n");
        return;
    }

    Node *current = q->head;

    if (current == NULL) {
        printf("Queue is empty\n");
        return;
    }

    printf("Queue contents:\n");

    while (current != NULL) {
        printf("%s\n", current->data);
        current = current->next;
    }
}

char *peek(Queue *q) {
    pthread_mutex_lock(&q->lock);
    char *data = q->head ? q->head->data : NULL;
    pthread_mutex_unlock(&q->lock);
    return data;
}