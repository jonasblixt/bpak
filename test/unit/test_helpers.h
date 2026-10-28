#ifndef BPAK_TEST_HELPERS_H
#define BPAK_TEST_HELPERS_H

/* cmocka.h depends on these being included first */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

/* Absolute path to a file in test/data */
#define TEST_DATA(name) BPAK_TEST_DATA_DIR "/" name

/* Read a whole file into a malloc'd buffer. Fails the test on error. */
size_t test_load_file(const char *path, uint8_t **buffer_out);

#endif
