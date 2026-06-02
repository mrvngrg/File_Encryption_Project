#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int encrypt_key(const unsigned char *private_key, int key_len, const char *pubkey, unsigned char *out, size_t *out_len) {
    
    BIO *bio = BIO_new_mem_buf(pubkey, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) { 
        printf("failed to load public key\n"); 
        ERR_print_errors_fp(stderr); 
        return -1; 
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { printf("ctx failed\n"); return -1; }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) { printf("encrypt init failed\n"); ERR_print_errors_fp(stderr); return -1; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) { printf("padding failed\n"); return -1; }

    size_t actual_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &actual_len, private_key, key_len) <= 0) { 
        printf("encrypt size failed\n"); 
        ERR_print_errors_fp(stderr); 
        return -1; 
    }
    if (EVP_PKEY_encrypt(ctx, out, &actual_len, private_key, key_len) <= 0) { 
        printf("encrypt failed\n"); 
        ERR_print_errors_fp(stderr); 
        return -1; 
    }
    *out_len = actual_len;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}