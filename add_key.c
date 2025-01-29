#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <keyutils.h>
#include <fcntl.h>
#include <errno.h>

#define KEYCTL_NEWRING     27

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <der_file>\n", argv[0]);
        return 1;
    }

    // Read the DER file
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Get file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Allocate buffer
    unsigned char *buffer = malloc(size);
    if (!buffer) {
        perror("malloc");
        close(fd);
        return 1;
    }

    // Read file
    if (read(fd, buffer, size) != size) {
        perror("read");
        free(buffer);
        close(fd);
        return 1;
    }
    close(fd);

    // First add the key to the session keyring
    key_serial_t key_id = add_key("asymmetric", ".ebpf:signing:x509", buffer, size, KEY_SPEC_SESSION_KEYRING);
    if (key_id < 0) {
        perror("add_key");
        free(buffer);
        return 1;
    }
    printf("Added key with ID: %d\n", key_id);

    // Create a new keyring in the session keyring
    key_serial_t keyring_id = add_key("keyring", "_ebpf", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    if (keyring_id < 0) {
        perror("Failed to create keyring");
        free(buffer);
        return 1;
    }
    printf("Created keyring with ID: %d\n", keyring_id);

    // Link the key to the keyring
    if (keyctl_link(key_id, keyring_id) < 0) {
        perror("keyctl_link");
        free(buffer);
        return 1;
    }
    printf("Linked key %d to keyring %d\n", key_id, keyring_id);

    free(buffer);
    return 0;
}
