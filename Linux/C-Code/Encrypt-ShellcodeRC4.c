#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rc4.h>

unsigned char key[16] = "0123456789012345"; // RC4 key

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *ciphertext) {
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, strlen((char *)key), key);
    RC4(&rc4_key, plaintext_len, plaintext, ciphertext);
}

int main() {

     if (argc != 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }

    int buf_len;
    unsigned char *buf = readBufferFromFile(argv[1], &buf_len);
    if (buf == NULL) {
        return 1;
    }

    
    int plaintext_len = sizeof(plaintext) - 1;
    unsigned char ciphertext[plaintext_len];

    encrypt(plaintext, plaintext_len, key, ciphertext);

    FILE *f = fopen("encoded_payload.h", "w");
    if (!f) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fprintf(f, "unsigned char encoded_payload[] = \n\"");
    for (int i = 0; i < plaintext_len; i++) {
        fprintf(f, "\\x%02x", ciphertext[i]);
        if ((i + 1) % 16 == 0 && i != plaintext_len - 1) {
            fprintf(f, "\"\n\"");
        }
    }
    fprintf(f, "\";\n");
    fclose(f);

    return 0;
}
