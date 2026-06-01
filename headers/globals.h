#ifndef GLOBALS_H
#define GLOBALS_H

#include "queue.h"
#include <stdbool.h>

typedef struct {
    unsigned char masked_key[16];
    unsigned char mask[16];
} Key;

extern Key key;

extern Queue queue;
extern const char *start_path;
//extern unsigned char key[16];
extern bool encryption_active;

void store_key(unsigned char *raw_key);
void use_key(unsigned char *out);
void wipe_key(unsigned char *buf);

#endif