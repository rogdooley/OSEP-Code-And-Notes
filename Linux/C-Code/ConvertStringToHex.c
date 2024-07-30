#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hex(const char *input) {
    size_t len = strlen(input);

    // Loop through each character in the input string
    for (size_t i = 0; i < len; i++) {
        // Print each character as a two-digit hexadecimal number
        printf("\\x%02x", (unsigned char)input[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s \"<string>\"\n", argv[0]);
        return 1;
    }

    // Input string to be converted to hex byte array
    const char *input = argv[1];

    // Print the input string as a hex byte array
    printf("Hex byte array:\n");
    print_hex(input);

    return 0;
}
