#ifndef QUEUE_H
#define QUEUE_H
#include <pthread.h>

typedef struct Node {
    int socketfd;
    struct Node *next;
} Node;

typedef struct Queue {
    Node *head;
    Node *tail;
    pthread_mutex_t lock;
} Queue;

void initializeQueue(Queue *q);

void enqueue(Queue *q, int socketfd);

int dequeue(Queue *q);

void remove_by_value(Queue *q, int value);

#endif  