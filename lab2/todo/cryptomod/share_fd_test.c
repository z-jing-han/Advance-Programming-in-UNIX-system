#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "cryptomod.h"

#define DEV_PATH "/dev/cryptodev"
#define DEFAULT_THREADS 8
#define DEFAULT_ITERS 20
#define CHUNK_LEN CM_BLOCK_SIZE   // one block per thread, keeps padding math trivial
#define MAX_BUF 4096

static int shared_fd = -1;
static pthread_barrier_t barrier;

struct writer_arg {
    int id;
    int write_ok;
};

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x ", data[i]);
    printf("\n");
}

// Only write() is exercised concurrently here. SETUP happens exactly once,
// single-threaded, before any thread starts — so this never touches the
// session-ownership problem (interleaved SETUP calls). It isolates exactly
// the internal race in cryptomod_dev_write() on cur_kernel_buffer_pos.
static void *writer(void *arg) {
    struct writer_arg *w = (struct writer_arg *)arg;
    unsigned char chunk[CHUNK_LEN];
    memset(chunk, 0x10 + w->id, CHUNK_LEN);

    pthread_barrier_wait(&barrier);

    ssize_t n = write(shared_fd, chunk, CHUNK_LEN);
    w->write_ok = (n == CHUNK_LEN);
    return NULL;
}

static int run_once(int nthreads, int verbose) {
    struct CryptoSetup setup_enc = { .key_len = 16, .c_mode = ENC, .io_mode = BASIC };
    memcpy(setup_enc.key, "1234567890abcdef", 16);

    if (ioctl(shared_fd, CM_IOC_SETUP, &setup_enc) < 0) {
        if (verbose) perror("  ioctl(SETUP-ENC)");
        return 0;
    }

    pthread_t *tids = malloc(sizeof(pthread_t) * nthreads);
    struct writer_arg *args = calloc(nthreads, sizeof(struct writer_arg));
    pthread_barrier_init(&barrier, NULL, nthreads);

    for (int i = 0; i < nthreads; i++) {
        args[i].id = i;
        if (pthread_create(&tids[i], NULL, writer, &args[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }
    for (int i = 0; i < nthreads; i++) {
        pthread_join(tids[i], NULL);
    }
    pthread_barrier_destroy(&barrier);

    int all_writes_ok = 1;
    for (int i = 0; i < nthreads; i++) {
        if (!args[i].write_ok) all_writes_ok = 0;
    }
    free(tids);
    free(args);

    if (!all_writes_ok) {
        if (verbose) printf("  at least one write() did not return CHUNK_LEN\n");
        return 0;
    }

    if (ioctl(shared_fd, CM_IOC_FINALIZE) < 0) {
        if (verbose) perror("  ioctl(FINALIZE-ENC)");
        return 0;
    }

    unsigned char cipher[MAX_BUF];
    ssize_t cipher_len = read(shared_fd, cipher, sizeof(cipher));
    if (cipher_len < 0) {
        if (verbose) perror("  read(ENC)");
        return 0;
    }
    ioctl(shared_fd, CM_IOC_CLEANUP);

    struct CryptoSetup setup_dec = { .key_len = 16, .c_mode = DEC, .io_mode = BASIC };
    memcpy(setup_dec.key, "1234567890abcdef", 16);
    if (ioctl(shared_fd, CM_IOC_SETUP, &setup_dec) < 0) {
        if (verbose) perror("  ioctl(SETUP-DEC)");
        return 0;
    }
    if (write(shared_fd, cipher, cipher_len) != cipher_len) {
        if (verbose) perror("  write(DEC)");
        return 0;
    }
    if (ioctl(shared_fd, CM_IOC_FINALIZE) < 0) {
        if (verbose) perror("  ioctl(FINALIZE-DEC)");
        return 0;
    }

    unsigned char plain[MAX_BUF];
    ssize_t plain_len = read(shared_fd, plain, sizeof(plain));
    ioctl(shared_fd, CM_IOC_CLEANUP);

    if (plain_len != (ssize_t)(nthreads * CHUNK_LEN)) {
        if (verbose) printf("  length mismatch: got %zd bytes, expected %d\n", plain_len, nthreads * CHUNK_LEN);
        return 0;
    }

    int seen[256] = {0};
    for (int i = 0; i < nthreads; i++) {
        unsigned char *win = plain + i * CHUNK_LEN;
        unsigned char v = win[0];
        int torn = 0;
        for (int j = 1; j < CHUNK_LEN; j++) {
            if (win[j] != v) { torn = 1; break; }
        }
        if (torn) {
            if (verbose) {
                printf("  torn chunk at window %d: ", i);
                print_hex(win, CHUNK_LEN);
            }
            return 0;
        }
        seen[v]++;
    }

    for (int i = 0; i < nthreads; i++) {
        unsigned char sig = 0x10 + i;
        if (seen[sig] != 1) {
            if (verbose) printf("  signature 0x%02x appeared %d time(s) (expected 1)\n", sig, seen[sig]);
            return 0;
        }
    }

    return 1;
}

int main(int argc, char **argv) {
    int nthreads = argc > 1 ? atoi(argv[1]) : DEFAULT_THREADS;
    int iters = argc > 2 ? atoi(argv[2]) : DEFAULT_ITERS;
    if (nthreads < 2) nthreads = 2;
    if (nthreads * CHUNK_LEN > MAX_BUF) {
        fprintf(stderr, "too many threads for one buffer\n");
        return 1;
    }

    shared_fd = open(DEV_PATH, O_RDWR);
    if (shared_fd < 0) {
        perror("open");
        return 1;
    }
    printf("Opened %s once as fd=%d. %d threads x %d iterations.\n", DEV_PATH, shared_fd, nthreads, iters);

    int pass = 0;
    for (int it = 0; it < iters; it++) {
        int ok = run_once(nthreads, 1);
        printf("[iter %2d] %s\n", it, ok ? "PASS" : "FAIL");
        if (ok) pass++;
    }

    close(shared_fd);
    printf("\n%d/%d iterations passed.\n", pass, iters);
    return pass == iters ? 0 : 1;
}
