// fathom-selftest -- the first thing to run on Fathom.
//
// Deliberately exercises one area of the emulator per section, in increasing order of
// how much has to be working, and prints a PASS/FAIL line for each. If the whole thing
// runs to "all checks passed" then the JIT, the loader, the process-entry stack and the
// syscall layer are all doing their jobs.
//
// Built static-pie so it can be placed anywhere in the guest address space -- see the
// README's note on why non-PIE binaries have nowhere to go on iOS.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>

static int failures = 0;

static void check(const char *name, int ok, const char *detail) {
    printf("  [%s] %-22s %s\n", ok ? "PASS" : "FAIL", name, detail ? detail : "");
    if (!ok) {
        failures++;
    }
}

// --- CPU: integer, floating point and SSE all go through FEXCore's JIT --------------

static void test_cpu(void) {
    printf("\nCPU (the JIT is translating this)\n");

    unsigned long long accumulator = 1;
    for (int i = 1; i <= 20; i++) {
        accumulator *= (unsigned long long)i;
    }
    char detail[64];
    snprintf(detail, sizeof(detail), "20! = %llu", accumulator);
    check("integer", accumulator == 2432902008176640000ULL, detail);

    // 80-bit x87 long double, which is emulated rather than native on ARM64 -- the
    // "reduced-precision x87" setting changes exactly this.
    long double pi = 0.0L;
    for (int i = 0; i < 1000000; i++) {
        pi += (i % 2 ? -1.0L : 1.0L) / (2.0L * i + 1.0L);
    }
    pi *= 4.0L;
    snprintf(detail, sizeof(detail), "pi ~ %.6f", (double)pi);
    check("x87 long double", pi > 3.14158 && pi < 3.14161, detail);

    // Vector maths, which compiles to NEON.
    double vector[8];
    for (int i = 0; i < 8; i++) {
        vector[i] = i * 1.5;
    }
    double sum = 0;
    for (int i = 0; i < 8; i++) {
        sum += vector[i] * vector[i];
    }
    snprintf(detail, sizeof(detail), "sum of squares = %.1f", sum);
    check("sse/vector", sum == 315.0, detail);

    // A branchy, data-dependent loop: this is what makes the JIT compile many small
    // blocks rather than one straight line.
    int primes = 0;
    for (int n = 2; n < 10000; n++) {
        int is_prime = 1;
        for (int d = 2; d * d <= n; d++) {
            if (n % d == 0) { is_prime = 0; break; }
        }
        primes += is_prime;
    }
    snprintf(detail, sizeof(detail), "%d primes below 10000", primes);
    check("branches", primes == 1229, detail);
}

// --- Memory: malloc walks brk and mmap ---------------------------------------------

static void test_memory(void) {
    printf("\nMemory (brk and mmap)\n");

    char *small = malloc(4096);
    check("small malloc", small != NULL, "4 KB");
    if (small) {
        memset(small, 0xAB, 4096);
        check("small write", (unsigned char)small[4095] == 0xAB, "readback ok");
        free(small);
    }

    // Big enough that glibc/musl reach for mmap rather than extending the heap.
    size_t big_size = 8 * 1024 * 1024;
    char *big = malloc(big_size);
    check("large malloc", big != NULL, "8 MB");
    if (big) {
        memset(big, 0x5C, big_size);
        int ok = 1;
        for (size_t i = 0; i < big_size; i += 65536) {
            if ((unsigned char)big[i] != 0x5C) { ok = 0; break; }
        }
        check("large write", ok, "8 MB touched and verified");
        free(big);
    }
}

// --- The process: argv, envp and the auxiliary vector -------------------------------

static void test_process(int argc, char **argv, char **envp) {
    printf("\nProcess (the entry stack Fathom built)\n");

    char detail[128];
    snprintf(detail, sizeof(detail), "argc=%d argv[0]=%s", argc, argc > 0 ? argv[0] : "(none)");
    check("argv", argc > 0 && argv[0] != NULL, detail);

    int env_count = 0;
    const char *fathom_marker = NULL;
    for (char **e = envp; *e; e++) {
        env_count++;
        if (strncmp(*e, "FATHOM=", 7) == 0) {
            fathom_marker = *e;
        }
    }
    snprintf(detail, sizeof(detail), "%d variables, %s", env_count,
             fathom_marker ? fathom_marker : "no FATHOM marker");
    check("environment", env_count > 0, detail);

    snprintf(detail, sizeof(detail), "pid=%d uid=%d", getpid(), getuid());
    check("pid/uid", getpid() > 0, detail);

    struct utsname name;
    if (uname(&name) == 0) {
        snprintf(detail, sizeof(detail), "%s %s %s", name.sysname, name.release, name.machine);
        check("uname", strcmp(name.machine, "x86_64") == 0, detail);
    } else {
        check("uname", 0, "call failed");
    }
}

// --- Time ---------------------------------------------------------------------------

static void test_time(void) {
    printf("\nTime\n");

    struct timespec start, end;
    int ok = clock_gettime(CLOCK_MONOTONIC, &start) == 0;
    check("clock_gettime", ok, "CLOCK_MONOTONIC");

    volatile unsigned long long spin = 0;
    for (int i = 0; i < 3000000; i++) {
        spin += i;
    }

    if (ok && clock_gettime(CLOCK_MONOTONIC, &end) == 0) {
        double elapsed = (double)(end.tv_sec - start.tv_sec)
                       + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
        char detail[64];
        snprintf(detail, sizeof(detail), "3M adds in %.3fs", elapsed);
        // A clock that never advances is a much more common failure than a slow one.
        check("monotonic advances", elapsed > 0.0 && elapsed < 120.0, detail);
    }

    time_t now = time(NULL);
    char detail[64];
    snprintf(detail, sizeof(detail), "unix time %ld", (long)now);
    check("time", now > 1600000000, detail);
}

// --- Files --------------------------------------------------------------------------

static void test_files(void) {
    printf("\nFiles (guest root filesystem)\n");

    const char *path = "/fathom-selftest.txt";
    const char *payload = "written by the guest\n";

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        check("open for write", 0, "could not create a file in the guest root");
        return;
    }
    ssize_t written = write(fd, payload, strlen(payload));
    close(fd);
    check("write", written == (ssize_t)strlen(payload), "wrote a file");

    char buffer[128] = {0};
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        check("open for read", 0, "could not reopen it");
        return;
    }
    ssize_t got = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    check("read back", got == written && strcmp(buffer, payload) == 0, buffer);

    struct stat info;
    char detail[64];
    if (stat(path, &info) == 0) {
        snprintf(detail, sizeof(detail), "%lld bytes", (long long)info.st_size);
        check("stat", info.st_size == written, detail);
    } else {
        check("stat", 0, "call failed");
    }

    unlink(path);
}

int main(int argc, char **argv, char **envp) {
    printf("fathom-selftest\n");
    printf("x86-64 Linux, running under FEXCore on ARM64\n");

    test_cpu();
    test_memory();
    test_process(argc, argv, envp);
    test_time();
    test_files();

    printf("\n");
    if (failures == 0) {
        printf("all checks passed\n");
    } else {
        printf("%d check%s failed\n", failures, failures == 1 ? "" : "s");
    }
    return failures == 0 ? 0 : 1;
}
