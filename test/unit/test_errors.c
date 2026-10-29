#include <bpak/bpak.h>
#include "test_helpers.h"

static void test_error_codes(void **state)
{
    (void)state;
    const char *unknown = bpak_error_string(1);

    /* Every error code should have a description */
    for (int i = BPAK_OK; i <= BPAK_EXISTS; i++) {
        assert_ptr_not_equal(bpak_error_string(-i), unknown);
    }

    assert_ptr_equal(bpak_error_string(-(BPAK_EXISTS + 1)), unknown);
}

static void test_error_strings(void **state)
{
    (void)state;
    assert_string_equal(bpak_error_string(BPAK_OK), "OK");
    assert_string_equal(bpak_error_string(-BPAK_FAILED), "Failed");
    assert_string_equal(bpak_error_string(-BPAK_NOT_FOUND), "Not found");
    assert_string_equal(bpak_error_string(-BPAK_SIZE_ERROR), "Size error");
    assert_string_equal(bpak_error_string(-BPAK_NO_SPACE_LEFT),
                        "No space left");
    assert_string_equal(bpak_error_string(-BPAK_BAD_ALIGNMENT),
                        "Bad alignment");
    assert_string_equal(bpak_error_string(-BPAK_SEEK_ERROR), "Seek error");
    assert_string_equal(bpak_error_string(-BPAK_NOT_SUPPORTED),
                        "Not supported");
    assert_string_equal(bpak_error_string(-999999), "Unknown");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_error_codes),
        cmocka_unit_test(test_error_strings),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
