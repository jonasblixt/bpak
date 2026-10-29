#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

static unsigned int tagged_allocations;

/* An allocator that tags its allocations, freeing anything else fails */
static void *tagged_calloc(size_t nmemb, size_t size)
{
    uint32_t *p = calloc(1, nmemb * size + 16);

    assert_non_null(p);
    *p = 0x62706b61u;
    tagged_allocations++;
    return (uint8_t *)p + 16;
}

static void tagged_free(void *ptr)
{
    if (ptr == NULL)
        return;

    uint32_t *p = (uint32_t *)((uint8_t *)ptr - 16);

    assert_int_equal(*p, 0x62706b61u);
    tagged_allocations--;
    *p = 0;
    free(p);
}

/* Create an empty package in a temporary file */
static void create_package(struct bpak_package *pkg, char *path)
{
    int fd = mkstemp(path);
    int rc;

    assert_true(fd >= 0);
    close(fd);

    rc = bpak_pkg_open(pkg, path, "r+b");
    assert_int_equal(rc, BPAK_OK);
}

static void test_add_key_allocator(void **state)
{
    (void)state;
    struct bpak_package pkg;
    char path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package(&pkg, path);

    tagged_allocations = 0;
    assert_int_equal(bpak_set_calloc_free(tagged_calloc, tagged_free), BPAK_OK);

    rc = bpak_pkg_add_key(&pkg, TEST_DATA("secp256r1-pub-key.der"), "key", 0);

    assert_int_equal(bpak_set_calloc_free(calloc, free), BPAK_OK);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(tagged_allocations, 0);

    bpak_pkg_close(&pkg);
    unlink(path);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signature_too_large),
        cmocka_unit_test(test_verify_signature_size),
        cmocka_unit_test(test_add_key_allocator),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
