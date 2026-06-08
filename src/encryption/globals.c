#include <stdbool.h>
#include <openssl/rand.h>
#include <sys/mman.h>

#include "../../headers/globals.h"

Queue queue;
//const char *start_path = "/home/nicolas-berger/Documents/Safe/test_encryption";
// const char *start_path = "/home/drikson/University/os/test";
//const char *start_path = "/home/vboxuser/test";
//const char *start_path = "/home/simon/Desktop/test";
const char *start_path = "/home";

pthread_mutex_t gui_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t gui_cond = PTHREAD_COND_INITIALIZER;

// bool encryption_active = false;
bool watcher_on = true;

Key key;

void store_key(unsigned char *raw_key) {
    RAND_bytes(key.mask, 16);
    for (int i = 0; i < 16; i++) {
        key.masked_key[i] = raw_key[i] ^ key.mask[i];
    }
    mlock(&key, sizeof(key));
    OPENSSL_cleanse(raw_key, 16);
}

// Call this every time you need the key
void use_key(unsigned char *out) {
    for (int i = 0; i < 16; i++) {
        out[i] = key.masked_key[i] ^ key.mask[i];
    }
}

// Call this after you are done using the key
void wipe_key(unsigned char *buf) {
    OPENSSL_cleanse(buf, 16);
}