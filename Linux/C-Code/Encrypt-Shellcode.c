#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

unsigned char* readBufferFromFile(const char *filename, int *buf_len) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    char line[256];
    unsigned char *buffer = NULL;
    int buffer_size = 0;
    *buf_len = 0;

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "unsigned char buf[] =")) {
            while (fgets(line, sizeof(line), file)) {
                char *start = strchr(line, '\"') + 1;
                char *end = strrchr(line, '\"');
                if (!start || !end) continue;
                *end = '\0';

                size_t line_len = end - start;
                buffer = (unsigned char *)realloc(buffer, buffer_size + line_len / 4);
                unsigned char *ptr = buffer + buffer_size;

                for (char *ch = start; ch < end; ch += 4) {
                    sscanf(ch, "\\x%2hhx", ptr++);
                    (*buf_len)++;
                }
                buffer_size += line_len / 4;
            }
            break;
        }
    }

    fclose(file);
    return buffer;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
        return 1;
    }

    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 256-bit key
    unsigned char *iv = (unsigned char *)"0123456789012345"; // 128-bit IV

    int buf_len;
    unsigned char *buf = readBufferFromFile(argv[1], &buf_len);
    if (buf == NULL) {
        return 1;
    }

    unsigned char ciphertext[128];
    encrypt(buf, buf_len, key, iv, ciphertext);

    FILE *f = fopen("encoded_payload.h", "w");
    if (f == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fprintf(f, "unsigned char buf[] = \n\"");
    for (int i = 0; i < buf_len + AES_BLOCK_SIZE; i++) {
        fprintf(f, "\\x%02x", ciphertext[i]);
    }
    fprintf(f, "\";\n");

    fclose(f);
    free(buf);

    return 0;
}
