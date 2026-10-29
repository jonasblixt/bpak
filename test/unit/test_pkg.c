#include <string.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include "test_helpers.h"

static void test_signature_too_large(void **state)
{
    (void)state;
    struct bpak_package pkg;
    uint8_t signature[BPAK_SIGNATURE_MAX_BYTES + 1] = { 0 };
    int rc;

    memset(&pkg, 0, sizeof(pkg));

    /* Rejected before the header is changed or written */
    rc = bpak_pkg_write_raw_signature(&pkg, signature, sizeof(signature));
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_int_equal(pkg.header.signature_sz, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signature_too_large),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
