/*
 * Runs a fuzz target on files without libFuzzer, so that the seed corpus
 * and crash reproducers run as regression tests in the normal build.
 *
 * Usage: <target> <file or directory>...
 */

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <bpak/bpak.h>
#include "fuzz.h"

/* The library logs with BPAK_FUZZ_VERBOSE=<verbosity> */
int bpak_printf(int verbosity, const char *fmt, ...)
{
    const char *env = getenv("BPAK_FUZZ_VERBOSE");
    va_list args;

    if (env == NULL || verbosity > atoi(env))
        return BPAK_OK;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    return BPAK_OK;
}

static int run_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *data;
    long size;

    if (fp == NULL) {
        fprintf(stderr, "Could not open %s\n", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Could not get the size of %s\n", path);
        fclose(fp);
        return -1;
    }

    /* Exactly sized, so that AddressSanitizer detects reads past the end */
    data = malloc(size ? size : 1);

    if (data == NULL || fread(data, 1, size, fp) != (size_t)size) {
        fprintf(stderr, "Could not read %s\n", path);
        free(data);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    printf("Running %s (%ld bytes)\n", path, size);
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}

static int run_path(const char *path)
{
    struct stat st;
    struct dirent **entries;
    int n;
    int rc = 0;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "Could not stat %s\n", path);
        return -1;
    }

    if (!S_ISDIR(st.st_mode))
        return run_file(path);

    /* Sorted, so that the order is the same on every run */
    n = scandir(path, &entries, NULL, alphasort);

    if (n < 0) {
        fprintf(stderr, "Could not read the directory %s\n", path);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        char file_path[4096];

        if (entries[i]->d_name[0] != '.') {
            snprintf(file_path,
                     sizeof(file_path),
                     "%s/%s",
                     path,
                     entries[i]->d_name);

            if (run_path(file_path) != 0)
                rc = -1;
        }

        free(entries[i]);
    }

    free(entries);
    return rc;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file or directory>...\n", argv[0]);
        return 2;
    }

    for (int i = 1; i < argc; i++) {
        if (run_path(argv[i]) != 0)
            rc = 1;
    }

    return rc;
}
