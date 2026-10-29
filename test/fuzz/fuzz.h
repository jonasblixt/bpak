#ifndef BPAK_TEST_FUZZ_H
#define BPAK_TEST_FUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* Entry point of a fuzz target, called by libFuzzer or by driver.c */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* A broken library contract, report it as a crash */
#define FUZZ_ASSERT(_cond)                                                     \
    do {                                                                       \
        if (!(_cond)) {                                                        \
            fprintf(stderr,                                                    \
                    "%s:%d: assertion failed: %s\n",                           \
                    __FILE__,                                                  \
                    __LINE__,                                                  \
                    #_cond);                                                   \
            abort();                                                           \
        }                                                                      \
    } while (0)

#endif
