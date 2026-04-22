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

void remove_by_value(Queue *q, const char *value) {
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
    char *data = q->head ? q->head->data : NULL;
    return data;
}