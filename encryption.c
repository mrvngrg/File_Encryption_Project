#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void encrypt_file(char *file, unsigned char* key, unsigned char* iv){

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    FILE *in = fopen(file, "rb");
    if (in == NULL){
        printf("cannot open %s file", file); 
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
                /* handle error */ 
            }
            buffer = tmp; 
        }

        EVP_EncryptUpdate(ctx, buffer + size, &outlen, temp, bytes);
        size += outlen; 
    }

    fclose(in);

    FILE *out = fopen(file, "wb");
    if (out == NULL){
        printf("cannot open %s file", file); 
    }

    fwrite(iv, 1 ,16, out);

    EVP_EncryptFinal_ex(ctx, buffer + size, &outlen);
    fwrite(buffer, 1, size + outlen, out);
    
    // TODO: schould rename the file to .locked

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);
}

void decrypt_file(char *file, unsigned char* key){
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
                /* handle error */ 
            }
            buffer = tmp; 
        }

        EVP_DecryptUpdate(ctx, buffer + size, &outlen, temp, bytes);
        size += outlen; 
    }

    fclose(in);

    FILE *out = fopen(file, "wb");
    if (out == NULL){
        printf("cannot open %s file", file); 
    }
    
    EVP_DecryptFinal_ex(ctx, buffer, &outlen);
    fwrite(buffer, 1, size + outlen, out);
    
    // TODO: schould rename the file (remove .locked)

    free(buffer);
    EVP_CIPHER_CTX_free(ctx);
    fclose(out);
}

int main()
{
    unsigned char iv[16];
    //RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    unsigned char key[16] = "qwertyuiopasdfgh";

    char *file = "sample.pdf";

    encrypt_file(file, key, iv);
    //decrypt_file(file, key);

    return 0;
}
