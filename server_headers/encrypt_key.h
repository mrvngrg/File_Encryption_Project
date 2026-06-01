#include <stdlib.h>
int encrypt_key(const unsigned char *private_key, int key_len, const char *pubkey, unsigned char *out, size_t *out_len);