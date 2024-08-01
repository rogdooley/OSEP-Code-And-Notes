#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Define the size of the AES key and IV
#define AES_KEYLEN 256
#define AES_KEYBYTES (AES_KEYLEN / 8)
#define AES_IVLEN 128
#define AES_IVBYTES (AES_IVLEN / 8)

// Function to read the shellcode from a file
unsigned char *read_shellcode(const char *filename, size_t *length) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(*length);
    if (buffer == NULL) {
        perror("malloc");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fread(buffer, 1, *length, file);
    fclose(file);

    return buffer;
}

// Function to write the new header file
void write_header_file(const unsigned char *key, const unsigned char *iv, const unsigned char *encrypted_payload, size_t encrypted_payload_len) {
    FILE *header_file = fopen("encrypted_payload_aes.h", "w");
    if (header_file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fprintf(header_file, "#ifndef ENCRYPTED_PAYLOAD_AES_H\n");
    fprintf(header_file, "#define ENCRYPTED_PAYLOAD_AES_H\n\n");

    fprintf(header_file, "unsigned char aes_key[] = {");
    for (int i = 0; i < AES_KEYBYTES; i++) {
        fprintf(header_file, "0x%02x", key[i]);
        if (i < AES_KEYBYTES - 1) {
            fprintf(header_file, ", ");
        }
    }
    fprintf(header_file, "};\n\n");

    fprintf(header_file, "unsigned char aes_iv[] = {");
    for (int i = 0; i < AES_IVBYTES; i++) {
        fprintf(header_file, "0x%02x", iv[i]);
        if (i < AES_IVBYTES - 1) {
            fprintf(header_file, ", ");
        }
    }
    fprintf(header_file, "};\n\n");

    fprintf(header_file, "unsigned char encrypted_payload[] = {\n");
    for (size_t i = 0; i < encrypted_payload_len; i++) {
        fprintf(header_file, "0x%02x", encrypted_payload[i]);
        if (i < encrypted_payload_len - 1) {
            fprintf(header_file, ", ");
        }
        if ((i + 1) % 16 == 0) {
            fprintf(header_file, "\n");
        }
    }
    fprintf(header_file, "\n};\n\n");

    fprintf(header_file, "#define ENCRYPTED_PAYLOAD_LEN %zu\n\n", encrypted_payload_len);

    fprintf(header_file, "#endif\n");

    fclose(header_file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shellcode_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    size_t payload_len;
    unsigned char *buf = read_shellcode(argv[1], &payload_len);

    // Allocate memory for the AES key and IV
    unsigned char key[AES_KEYBYTES];
    unsigned char iv[AES_IVBYTES];

    // Generate random AES key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating random bytes.\n");
        return EXIT_FAILURE;
    }

    // Allocate memory for the encrypted payload
    size_t encrypted_payload_len = ((payload_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *encrypted_payload = malloc(encrypted_payload_len);
    if (encrypted_payload == NULL) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    // Initialize the AES key structure
    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, AES_KEYLEN, &enc_key) < 0) {
        fprintf(stderr, "Error setting AES encryption key.\n");
        return EXIT_FAILURE;
    }

    // Encrypt the payload using AES in CBC mode
    AES_cbc_encrypt(buf, encrypted_payload, payload_len, &enc_key, iv, AES_ENCRYPT);

    // Write the new header file
    write_header_file(key, iv, encrypted_payload, encrypted_payload_len);

    // Clean up
    free(buf);
    free(encrypted_payload);

    return 0;
}
