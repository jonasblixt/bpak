#include <stdbool.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/id.h>
#include <bpak/verify.h>
#include "test_helpers.h"

static void init_test_header(struct bpak_header *h)
{
    struct bpak_meta_header *meta;
    struct bpak_part_header *part;

    bpak_init_header(h);
    assert_int_equal(bpak_add_meta(h, bpak_id("bpak-version"), 0, 6, &meta),
                     BPAK_OK);
    memcpy(bpak_get_meta_ptr(h, meta, char), "1.0.0", 6);
    assert_int_equal(bpak_add_part(h, bpak_id("data"), &part), BPAK_OK);
    part->size = 1000;
    part->pad_bytes = 24;
    bpak_set_key_id(h, bpak_id("key"));
    bpak_set_keystore_id(h, bpak_id("keystore"));
}

static bool header_hash_equal(struct bpak_header *h, const uint8_t *expected,
                              size_t expected_size)
{
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t size = sizeof(hash);

    /* Changing hash_kind can make the hash fail, that changes the hash
     * as well */
    if (bpak_verify_compute_header_hash(h, hash, &size) != BPAK_OK)
        return false;

    return (size == expected_size) && (memcmp(hash, expected, size) == 0);
}

/* The header hash is what gets signed. It must cover every byte of the
 * header except the signature itself. */
static void test_header_hash_coverage(void **state)
{
    (void)state;
    struct bpak_header h;
    uint8_t *raw = (uint8_t *)&h;
    uint8_t expected[BPAK_HASH_MAX_LENGTH];
    size_t expected_size = sizeof(expected);
    const size_t signature_start = offsetof(struct bpak_header, signature);

    init_test_header(&h);
    assert_int_equal(bpak_verify_compute_header_hash(&h, expected,
                                                     &expected_size),
                     BPAK_OK);
    assert_int_equal(expected_size, 32);

    for (size_t i = 0; i < sizeof(h); i++) {
        raw[i] ^= 0x01;

        if (i < signature_start) {
            if (header_hash_equal(&h, expected, expected_size))
                fail_msg("Header byte %zu is not covered by the hash", i);
        } else {
            if (!header_hash_equal(&h, expected, expected_size))
                fail_msg("Signature byte %zu changes the hash", i);
        }

        raw[i] ^= 0x01;
    }
}

static void test_header_hash_buffer_too_small(void **state)
{
    (void)state;
    struct bpak_header h;
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t size = 16;

    init_test_header(&h);
    assert_int_equal(bpak_verify_compute_header_hash(&h, hash, &size),
                     -BPAK_SIZE_ERROR);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_header_hash_coverage),
        cmocka_unit_test(test_header_hash_buffer_too_small),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
