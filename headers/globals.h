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
extern bool encryption_active;
extern bool full_encryption_active;

extern pthread_mutex_t gui_mutex;
extern pthread_cond_t gui_cond;

void store_key(unsigned char *raw_key);
void use_key(unsigned char *out);
void wipe_key(unsigned char *buf);

#endif