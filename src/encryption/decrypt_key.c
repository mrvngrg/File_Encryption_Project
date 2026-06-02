#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "../../headers/globals.h"

const char *PRIVKEY =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDJaP/j7U7f6d7o\n"
"Ya2AEQ4tuIwWbgppieEVqEH/a/S1WGeUGnyPQ3XdNU5CwfeFOI3c7Qz6nuDfo+C3\n"
"h6856D1FqzRk+qmtNHDC69a79wSpOS4VK1EJDfL70ZPCG+5GljV11n7XlA6gR0iz\n"
"4w/SfiJmR4Vy+bHlTpyrKkkF4gLchIb5AgN/MGHhMQRmqSiQCjaKweWfOGek18sf\n"
"Z8h4BHDEe/h4ppu+MCZtjN4q3y5k761M4E+K/a5aLq8Ooud1zULann+bfMGEX3rZ\n"
"yCuYhugCAyfTv89UJCHcA07CgYOY7bMymdT4If1dQZsiPnI1uLiaiU2IzMI/PmZR\n"
"sNMHyO0fAgMBAAECggEAExLPe4ft+pnM6JgqHxZTumlfUtce7fmxss8EA6qh5PPh\n"
"8zjtkipNpMzh2W6XAIBnkYQda4p/jzjsv1SpIm8SMQvSjWbeNK83p9iVCv3h7Mij\n"
"yuYW6X2Zr4FHCzsr6HaxyglYamqfVqG0NTI2kworkHYLduTwlN+fSeevkfq3p1Gh\n"
"Qy0S+0NKKfNflYuD5GXyV5STjIOVX7sNuLiGwbAVjfxo0xc908BlT2uJ4r2qGegJ\n"
"2JdPZPEatJTxHVfSAihTj9nTH1ehJOndZW/1u0Z40FXYixZPxgfWnz+TzV5Y0hPJ\n"
"iuul26/RTUIivO5m/WkE8YQ0XSPXPkfrPDvj/sidUQKBgQDkFHb+TUpgFuroLJ4a\n"
"soMMfr035u9cCYXO8zQiXdif4Oq1cqYk2kCTYVKKuEPe0OSSCqDJUjvFlBY3ZW2q\n"
"0OF/8YR/TRKmcKW2+fW9SlvV9me/YG2lzmlDQhFJcD2r/q6FT51H7XPVj3dxbalE\n"
"21C4q5JDdLXYJUS1G8IQSXMSOQKBgQDiEMLPEDqP2kwYwGJp3bok2v3FZIE64MA1\n"
"hFbCRBJ3QPRuJf5yVvC6D/lR6PPZh6nFXiquSnI0b5lTVkm8isF61DNGEFifvH/F\n"
"al+r5JeMrySFoSPRmDmjuQ1TMz1+9NgPikD6IR5ygE68F6s4f3XiwzxeZy6y6Afm\n"
"zK0D8VyaFwKBgQDXGxny0xBPOa4IlHP0d+GyuiFZBLtAkVaajLLhqqKwfp69zEg3\n"
"v4NhvErtu8V+8oJv3ggwdxcaS4T8b/OTQ3c5hJ3Stezd/qW7wVjrUqL0U3UbgCVJ\n"
"WDfckAXfvjTb7tHHtwN+H8u8YZdj6enXoAQsdtv2NK+AD/4R1QEc/TjCuQKBgQCo\n"
"mtWgt7rltWuR/lKoIL4HZOlmgno73oqcn5JRm5GmLeTgDihDQQKT0vwhkjvk3uDJ\n"
"Gl181nttDlrto+qk21xIbuG6/NAMevtU0ux9+KTrQWlc3P0pAn7i1E7S4eGYwaYv\n"
"mO6zX2YlAfs3H/QM1EupD/IDerOCrbnO8pKL4UUuiwKBgQCMyeGr7QJ5AH7hf/SZ\n"
"ed2yk20YDvtnWKgcPhm06enQlFyn5fMbKYIHxZqc5ii7awmi1WcyUv+9UwWZehkY\n"
"IoXeAXa74gegoOVC+cd/oUF5+ETNhPteZdj9ehRLD9pUjEo22u3246UfJufeEh5a\n"
"pqdjOKAcN9E4oUNAkWYkNIF2dA==\n"
"-----END PRIVATE KEY-----\n";

void decrypt_key(unsigned char *encrypted) {
    BIO *bio = BIO_new_mem_buf(PRIVKEY, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        printf("failed to load private key\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    unsigned char raw_key[16];
    size_t raw_len = sizeof(raw_key);

    if (EVP_PKEY_decrypt(ctx, NULL, &raw_len, encrypted, 256) <= 0) {
        printf("decrypt size failed\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    if (EVP_PKEY_decrypt(ctx, raw_key, &raw_len, encrypted, 256) <= 0) {
        printf("decrypt failed\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    store_key(raw_key);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}