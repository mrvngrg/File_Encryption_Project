#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

char *encrypt_file(char *file, unsigned char* key) {
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    FILE *in = fopen(file, "rb");
    if (in == NULL){
        printf("cannot open %s file", file);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    char *buffer = NULL; 
    size_t size = 0; 
    size_t capacity = 0;

    char temp[4096];
    size_t bytes;

    int outlen;
    while ((bytes = fread(temp, 1, sizeof(temp), in)) > 0) { 

        if (size + bytes + 16 > capacity) {
            capacity = (capacity + bytes) * 2; 
            char *tmp = realloc(buffer, capacity);
            
            if (tmp == NULL) { 
                /* should handle error */ 
            }
            buffer = tmp; 
        }

        EVP_EncryptUpdate(ctx, buffer + size, &outlen, temp, bytes);
        size += outlen; 
    }

    fclose(in);

    if (buffer == NULL) {
        buffer = malloc(EVP_MAX_BLOCK_LENGTH);
        if (buffer == NULL) {
            fprintf(stderr, "malloc failed\n");
            fclose(in);
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }
        capacity = EVP_MAX_BLOCK_LENGTH;
    }

    FILE *out = fopen(file, "wb");
    if (out == NULL){
        printf("cannot open %s file", file); 
        free(buffer);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    fwrite(iv, 1 ,16, out);

    EVP_EncryptFinal_ex(ctx, buffer + size, &outlen);
    fwrite(buffer, 1, size + outlen, out);
    
    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);

    char *new_name = malloc(strlen(file) + 8);
    snprintf(new_name, strlen(file) + 8, "%s.locked", file);
    rename(file, new_name);
    return new_name;
}

char *decrypt_file(char *file, unsigned char* key) {
    FILE *in = fopen(file, "rb");
    if (in == NULL){
        printf("cannot locked file"); 
    }

    unsigned char iv[16];
    fread(iv, 1 , 16, in);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    char *buffer = NULL; 
    size_t size = 0; 
    size_t capacity = 0;

    char temp[4096];
    size_t bytes;

    int outlen;
    while ((bytes = fread(temp, 1, sizeof(temp), in)) > 0) { 

        if (size + bytes + 16 > capacity) {
            capacity = (capacity + bytes) * 2; 
            char *tmp = realloc(buffer, capacity);
            
            if (tmp == NULL) { 
                /* should handle error */ 
            }
            buffer = tmp; 
        }

        EVP_DecryptUpdate(ctx, buffer + size, &outlen, temp, bytes);
        size += outlen; 
    }

    fclose(in);

    if (buffer == NULL) {
        buffer = malloc(EVP_MAX_BLOCK_LENGTH);
        if (buffer == NULL) {
            fprintf(stderr, "malloc failed\n");
            fclose(in);
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }
        capacity = EVP_MAX_BLOCK_LENGTH;
    }

    FILE *out = fopen(file, "wb");
    if (out == NULL){
        printf("cannot open %s file", file); 
    }
    
    EVP_DecryptFinal_ex(ctx, buffer + size, &outlen);
    fwrite(buffer, 1, size + outlen, out);
    
    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);

    char *new_name = malloc(strlen(file) + 1); // +1 for null terminator
    if (new_name == NULL) return NULL;

    strcpy(new_name, file);

    size_t len = strlen(new_name);
    if (len > 7 && strcmp(new_name + len - 7, ".locked") == 0) {
        new_name[len - 7] = '\0';
        rename(file, new_name);
    }

    return new_name;
}