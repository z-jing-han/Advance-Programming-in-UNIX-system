#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "cryptomod.h"

#define DEV_PATH "/dev/cryptodev"

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    int fd;
    ssize_t written, rd;
    unsigned char encbuf[256], decbuf[256];
    // const char *plaintext = "HelloKernelAESTT";
    unsigned char plaintext[] = {
        0x0e, 0x0e, 0x00
    };
    size_t len = strlen(plaintext);

    // ---- Open device ----
    fd = open(DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("Device opened successfully.\n");

    // ---- Setup encryption ----
    struct CryptoSetup setup_enc = {
        .key_len = 16,
        .c_mode = ENC,
        .io_mode = BASIC
    };
    memcpy(setup_enc.key, "1234567890abcdef", 16);

    if (ioctl(fd, CM_IOC_SETUP, &setup_enc) < 0) {
        perror("ioctl(CM_IOC_SETUP - ENC)");
        close(fd);
        return 1;
    }
    printf("Encryption setup done.\n");

    // ---- Encrypt ----
    printf("Plaintext (%zu bytes):\n", len);
    print_hex(plaintext, len);

    written = write(fd, plaintext, len);
    if (written < 0) {
        perror("write (ENC)");
        close(fd);
        return 1;
    }

    if (ioctl(fd, CM_IOC_FINALIZE) < 0) {
        perror("ioctl(CM_IOC_FINALIZE - ENC)");
        close(fd);
        return 1;
    }

    rd = read(fd, encbuf, sizeof(encbuf));
    if (rd < 0) {
        perror("read (ENC)");
        close(fd);
        return 1;
    }
    printf("Encrypted data (%zd bytes):\n", rd);
    print_hex(encbuf, rd);

    // ---- Reset counters and cleanup after encryption ----
    ioctl(fd, CM_IOC_CNT_RST);
    ioctl(fd, CM_IOC_CLEANUP);

    // ---- Setup decryption ----
    struct CryptoSetup setup_dec = {
        .key_len = 16,
        .c_mode = DEC,
        .io_mode = BASIC
    };
    memcpy(setup_dec.key, "1234567890abcdef", 16);

    if (ioctl(fd, CM_IOC_SETUP, &setup_dec) < 0) {
        perror("ioctl(CM_IOC_SETUP - DEC)");
        close(fd);
        return 1;
    }
    printf("Decryption setup done.\n");

    // ---- Decrypt ----
    written = write(fd, encbuf, rd);
    if (written < 0) {
        perror("write (DEC)");
        close(fd);
        return 1;
    }

    if (ioctl(fd, CM_IOC_FINALIZE) < 0) {
        perror("ioctl(CM_IOC_FINALIZE - DEC)");
        close(fd);
        return 1;
    }

    ssize_t dec_len = read(fd, decbuf, sizeof(decbuf));
    if (dec_len < 0) {
        perror("read (DEC)");
        close(fd);
        return 1;
    }

    decbuf[dec_len] = '\0';
    // Print plaintext as hex
    printf("Plaintext (%zu bytes):\n", len);
    print_hex(plaintext, len);

    // After decryption, compare raw bytes
    if (dec_len == len && memcmp(plaintext, decbuf, len) == 0) {
        printf("Success: Decrypted bytes match original.\n");
    } else {
        printf("Mismatch!\nOriginal bytes:\n");
        print_hex(plaintext, len);
        printf("Decrypted bytes:\n");
        print_hex(decbuf, dec_len);
    }


    // ---- Cleanup ----
    ioctl(fd, CM_IOC_CNT_RST);
    ioctl(fd, CM_IOC_CLEANUP);
    close(fd);

    return 0;
}
