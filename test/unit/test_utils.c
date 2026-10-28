#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include "test_helpers.h"

static void test_bin2hex(void **state)
{
    (void)state;
    uint8_t data[] = {0x00, 0x7f, 0xa5, 0xff};
    /* Exactly fits the string and the null terminator */
    char *buf = malloc(sizeof(data) * 2 + 1);
    assert_non_null(buf);

    assert_int_equal(bpak_bin2hex(data, sizeof(data), buf, sizeof(data) * 2 + 1),
                     BPAK_OK);
    assert_string_equal(buf, "007fa5ff");

    free(buf);
}

static void test_bin2hex_buffer_too_small(void **state)
{
    (void)state;
    uint8_t data[BPAK_HASH_MAX_LENGTH];
    /* No room for the null terminator. AddressSanitizer catches writes
     * outside of the buffer. */
    char *buf = malloc(sizeof(data) * 2);
    assert_non_null(buf);

    memset(data, 0xab, sizeof(data));
    assert_int_not_equal(bpak_bin2hex(data, sizeof(data), buf, sizeof(data) * 2),
                         BPAK_OK);

    free(buf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bin2hex),
        cmocka_unit_test(test_bin2hex_buffer_too_small),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
