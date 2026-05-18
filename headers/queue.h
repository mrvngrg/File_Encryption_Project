#include <pthread.h>
#ifndef QUEUE_H
#define QUEUE_H

typedef struct Node {
    char *data;
    struct Node *next;
} Node;

typedef struct Queue {
    Node *head;
    Node *tail;
    pthread_mutex_t lock;
} Queue;

void initializeQueue(Queue *q);

void enqueue(Queue *q, const char *filepath);

char *dequeue(Queue *q);

char *get_element(Queue *q);

void remove_by_value(Queue *q, const char *value);

void print_queue(Queue *q);

char *peek(Queue *q);
#endif