#ifndef QUEUE_H
#define QUEUE_H

typedef struct Node {
    char *data;
    struct Node *next;
} Node;

typedef struct Queue {
    Node *head;
    Node *tail;
} Queue;

void initializeQueue(Queue *q);

void enqueue(Queue *q, char *filepath);

char *dequeue(Queue *q);

#endif