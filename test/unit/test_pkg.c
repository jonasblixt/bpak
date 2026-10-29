#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
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

static void test_verify_signature_size(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_key *key = NULL;
    int rc;

    rc = bpak_crypto_load_public_key(TEST_DATA("secp256r1-pub-key.der"), &key);
    assert_int_equal(rc, BPAK_OK);

    memset(&pkg, 0, sizeof(pkg));
    bpak_init_header(&pkg.header);

    /* A DER signature whose lengths reach past the signature field */
    static const uint8_t der[] = { 0x30, 0x82, 0xff, 0xfb,
                                   0x02, 0x82, 0xff, 0xf4 };
    memcpy(pkg.header.signature, der, sizeof(der));
    pkg.header.signature_sz = 0xffff;

    rc = bpak_pkg_verify(&pkg, key);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    pkg.header.signature_sz = sizeof(pkg.header.signature) + 1;
    rc = bpak_pkg_verify(&pkg, key);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    free(key);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signature_too_large),
        cmocka_unit_test(test_verify_signature_size),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
