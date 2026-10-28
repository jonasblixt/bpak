#include <stdio.h>
#include <stdlib.h>
#include <bpak/bpak.h>
#include "test_helpers.h"

/* Overrides the weak no-op in libbpak so library logs end up in test output */
int bpak_printf(int verbosity, const char *fmt, ...)
{
    (void)verbosity;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return BPAK_OK;
}

size_t test_load_file(const char *path, uint8_t **buffer_out)
{
    FILE *fp = fopen(path, "rb");
    assert_non_null(fp);

    assert_int_equal(fseek(fp, 0, SEEK_END), 0);
    long length = ftell(fp);
    assert_true(length > 0);
    rewind(fp);

    uint8_t *buffer = malloc(length);
    assert_non_null(buffer);
    assert_int_equal(fread(buffer, 1, length, fp), length);
    fclose(fp);

    *buffer_out = buffer;
    return (size_t)length;
}
