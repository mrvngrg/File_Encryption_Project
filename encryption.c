#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void encrypt_file(char *infile, char *outfile, unsigned char* key, unsigned char* iv){
    FILE *in = fopen(infile, "rb");
    if (in == NULL){
        printf("cannot open in file"); 
    }

    FILE *out = fopen(outfile, "wb");
    if (out == NULL){
        printf("cannot open out file"); 
    }

    fwrite(iv, 1 ,16, out); // for decryption

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);


    unsigned char inbuf[1024];
    unsigned char outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1 ,sizeof(inbuf), in)) > 0){
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1,outlen, out);
    }
    
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf,1,outlen,out);
    remove(infile);
    
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void decrypt_file(char *infile, char *outfile, unsigned char* key){
    FILE *in = fopen(infile, "rb");
    if (in == NULL){
        printf("cannot locked file"); 
    }

    FILE *out = fopen(outfile, "wb");
    if (out == NULL){
        printf("cannot recreate original file"); 
    }

    unsigned char iv[16];
    fread(iv, 1 , 16, in);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);


    unsigned char inbuf[1040];
    unsigned char outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1 ,sizeof(inbuf), in)) > 0){
        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1,outlen, out);
    }
    
    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf,1,outlen,out);
    remove(infile);
    
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

int main()
{
    unsigned char iv[16];
    //RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    unsigned char key[16] = "qwertyuiopasdfgh";

    char *orfile = "sample.pdf";
    char *lockfile = "sample.pdf.locked";
    char *outfile = "sample.pdf";

    //encrypt_file(orfile, lockfile, key, iv);
    decrypt_file(lockfile, outfile, key);

    return 0;
}
