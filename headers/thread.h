#ifndef THREAD_H
#define THREAD_H

#include <stdbool.h>

void initialize_threads(int n, bool encrypt);

void *runner(void *arg);

#endif