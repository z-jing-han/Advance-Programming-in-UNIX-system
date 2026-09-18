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

int test() {
    int fd;
    ssize_t written, rd;

    pid_t mypid = getpid();
    unsigned char sig = (unsigned char)(mypid & 0xFF);

    size_t len = 64;
    unsigned char plaintext[64], encbuf[128], decbuf[128];
    memset(plaintext, sig, len);

    // ---- Open device ----
    fd = open(DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    printf("[pid %d] Device opened successfully.\n", mypid);

    // ---- Setup encryption ----
    struct CryptoSetup setup_enc = {
        .key_len = 16,
        .c_mode = ENC,
        .io_mode = ADV
    };
    memcpy(setup_enc.key, "1234567890abcdef", 16);

    if (ioctl(fd, CM_IOC_SETUP, &setup_enc) < 0) {
        perror("ioctl(CM_IOC_SETUP - ENC)");
        close(fd);
        return 1;
    }
    printf("[pid %d] Encryption setup done.\n", mypid);

    // ---- Encrypt ----
    printf("[pid %d] Plaintext (%zu bytes):\n", mypid, len);
    // print_hex(plaintext, len);

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
    printf("[pid %d] Encrypted data (%zd bytes):\n", mypid, rd);
    // print_hex(encbuf, rd);

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
    printf("[pid %d] Decryption setup done.\n", mypid);

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
    printf("[pid %d] Plaintext (%zu bytes):\n", mypid, len);
    // print_hex(plaintext, len);

    // After decryption, compare raw bytes
    if (dec_len == (ssize_t)len && memcmp(plaintext, decbuf, len) == 0) {
        printf("[pid %d] Success: Decrypted bytes match original (sig=0x%02x).\n", mypid, sig);
    } else {
        printf("[pid %d] MISMATCH! expected all bytes = 0x%02x\n", mypid, sig);
        printf("Decrypted bytes:\n");
        print_hex(decbuf, dec_len);

        for (ssize_t i = 0; i < dec_len; i++) {
            if (decbuf[i] != sig) {
                printf("[pid %d]   -> byte[%zd] = 0x%02x  (looks like someone else's signature!)\n",
                       mypid, i, decbuf[i]);
                break;
            }
        }
    }

    // ---- Cleanup ----
    ioctl(fd, CM_IOC_CNT_RST);
    ioctl(fd, CM_IOC_CLEANUP);
    close(fd);

    return 0;
}

int main() {
    for (int i = 0; i < 2; ++i) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork() error");
            return 1;
        }
    }

    
    if (test() != 0) {
        printf("Some Error in test function\n");
    }

    return 0;
}
