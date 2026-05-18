#ifndef GLOBALS_H
#define GLOBALS_H

#include "queue.h"
#include <stdbool.h>

extern Queue queue;
extern const char *start_path;
extern unsigned char key[16];
extern bool encryption_active;

#endif