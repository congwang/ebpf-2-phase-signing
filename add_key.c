#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <keyutils.h>
#include <fcntl.h>

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

    // Get the keyring ID
    key_serial_t keyring_id = request_key("keyring", "_ebpf", NULL, KEY_SPEC_SESSION_KEYRING);
    if (keyring_id < 0) {
        perror("request_key");
        free(buffer);
        return 1;
    }

    // Add the key
    key_serial_t key_id = add_key("asymmetric", "system:ebpf:program-signing", buffer, size, keyring_id);
    if (key_id < 0) {
        perror("add_key");
        free(buffer);
        return 1;
    }

    printf("Added key with ID: %d\n", key_id);
    free(buffer);
    return 0;
}
