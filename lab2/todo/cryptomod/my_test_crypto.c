#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "cryptomod.h"

#define DEV_PATH "/dev/cryptodev"
#define PROC_PATH "/proc/cryptomod"

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    int fd = open(DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    printf("Device opened successfully.\n");

    struct CryptoSetup setup = {
        .key_len = 16,
        .c_mode = ENC,
        .io_mode = BASIC
    };
    memcpy(setup.key, "1234567890abcdef", 16);

    if (ioctl(fd, CM_IOC_SETUP, &setup) < 0) {
        perror("ioctl(CM_IOC_SETUP)");
        close(fd);
        return 1;
    }

    printf("Device setup done.\n");

    const char *plaintext = "HelloKernelAES";
    size_t len = strlen(plaintext);
    printf("Writing %zu bytes: %s\n", len, plaintext);

    ssize_t written = write(fd, plaintext, len);
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    printf("Wrote %zd bytes to kernel.\n", written);

    if (ioctl(fd, CM_IOC_FINALIZE) < 0) {
        perror("ioctl(CM_IOC_FINALIZE)");
        close(fd);
        return 1;
    }

    printf("Finalized encryption.\n");

    unsigned char encbuf[256];
    ssize_t rd = read(fd, encbuf, sizeof(encbuf));
    if (rd < 0) {
        perror("read");
        close(fd);
        return 1;
    }

    printf("Read %zd bytes from kernel.\n", rd);
    print_hex(encbuf, rd);

    // reset counters
    ioctl(fd, CM_IOC_CNT_RST);

    // cleanup
    ioctl(fd, CM_IOC_CLEANUP);

    close(fd);

    printf("\n--- /proc/cryptomod contents ---\n");
    FILE *proc = fopen(PROC_PATH, "r");
    if (proc) {
        char line[256];
        while (fgets(line, sizeof(line), proc)) {
            fputs(line, stdout);
        }
        fclose(proc);
    } else {
        perror("fopen(/proc/cryptomod)");
    }

    return 0;
}
