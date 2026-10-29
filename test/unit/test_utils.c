#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
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

static void test_hash_tree_id(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_part_header *part;

    bpak_init_header(&h);
    assert_int_equal(bpak_add_part(&h, bpak_id("rootfs"), &part), BPAK_OK);
    assert_int_equal(bpak_add_part(&h, bpak_id("kernel"), &part), BPAK_OK);

    bpak_id_t tree_id = bpak_part_name_to_hash_tree_id("kernel");

    /* The hash tree of a part is named '<part name>-hash-tree' */
    assert_int_equal(tree_id, bpak_id("kernel-hash-tree"));
    assert_int_equal(bpak_part_id_to_hash_tree_id(bpak_id("kernel")), tree_id);
    assert_int_equal(bpak_hash_tree_id_to_part_id(&h, tree_id),
                     bpak_id("kernel"));
    assert_int_equal(bpak_hash_tree_id_to_part_id(&h, bpak_id("other-hash-tree")),
                     0);
}

static void test_uuid_to_string(void **state)
{
    (void)state;
    const uint8_t uuid[16] = { 0x08, 0x88, 0xb0, 0xfa, 0x9c, 0x48, 0x45, 0x24,
                               0x98, 0x45, 0x06, 0xa6, 0x41, 0xb6, 0x1e, 0xdd };
    char buf[37];

    assert_int_equal(bpak_uuid_to_string(uuid, buf, sizeof(buf)), BPAK_OK);
    assert_string_equal(buf, "0888b0fa-9c48-4524-9845-06a641b61edd");

    assert_int_equal(bpak_uuid_to_string(uuid, buf, sizeof(buf) - 1),
                     -BPAK_SIZE_ERROR);
}

static void test_meta_to_string(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_meta_header *meta;
    const uint64_t load_addr = 0x80000000;
    char buf[128];
    int rc;

    bpak_init_header(&h);

    meta = test_add_meta_value(&h,
                               BPAK_ID_PB_LOAD_ADDR,
                               0,
                               &load_addr,
                               sizeof(load_addr));
    rc = bpak_meta_to_string(&h, meta, buf, sizeof(buf));
    assert_int_equal(rc, BPAK_OK);
    assert_string_equal(buf, "Entry: 0x80000000");

    meta = test_add_meta_value(&h, BPAK_ID_BPAK_VERSION, 0, "1.2.3", 6);
    rc = bpak_meta_to_string(&h, meta, buf, sizeof(buf));
    assert_int_equal(rc, BPAK_OK);
    assert_string_equal(buf, "1.2.3");

    /* Unknown meta data is an empty string */
    meta = test_add_meta_value(&h, bpak_id("test-meta"), 0, "x", 1);
    memset(buf, 'x', sizeof(buf));
    rc = bpak_meta_to_string(&h, meta, buf, sizeof(buf));
    assert_int_equal(rc, BPAK_OK);
    assert_string_equal(buf, "");
}

static void test_meta_to_string_sizes(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_meta_header *meta;
    uint8_t salt[32] = { 0 };
    char buf[128];
    int rc;

    bpak_init_header(&h);

    /* A version without the NUL that fills the buffer is terminated */
    meta = test_add_meta_value(&h, BPAK_ID_BPAK_VERSION, 0, "12345", 5);
    rc = bpak_meta_to_string(&h, meta, buf, 6);
    assert_int_equal(rc, BPAK_OK);
    assert_string_equal(buf, "12345");

    memset(buf, 'x', sizeof(buf));
    rc = bpak_meta_to_string(&h, meta, buf, 5);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_string_equal(buf, "");

    /* The hex string does not fit, the buffer was left uninitialized */
    meta = test_add_meta_value(&h, BPAK_ID_MERKLE_SALT, 0, salt, sizeof(salt));
    memset(buf, 'x', sizeof(buf));
    rc = bpak_meta_to_string(&h, meta, buf, 64);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_string_equal(buf, "");

    rc = bpak_meta_to_string(&h, meta, buf, 65);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(strlen(buf), 64);

    /* Truncated by snprintf */
    meta = test_add_meta_value(&h, BPAK_ID_KEYSTORE_PROVIDER_ID, 0, salt, 4);
    rc = bpak_meta_to_string(&h, meta, buf, 3);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_string_equal(buf, "");

    /* Meta data smaller than its type */
    meta = test_add_meta_value(&h, BPAK_ID_MERKLE_ROOT_HASH, 0, salt, 8);
    rc = bpak_meta_to_string(&h, meta, buf, sizeof(buf));
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_string_equal(buf, "");

    rc = bpak_meta_to_string(&h, meta, buf, 0);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
}

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
        cmocka_unit_test(test_bin2hex),
        cmocka_unit_test(test_bin2hex_buffer_too_small),
        cmocka_unit_test(test_hash_tree_id),
        cmocka_unit_test(test_uuid_to_string),
        cmocka_unit_test(test_meta_to_string),
        cmocka_unit_test(test_meta_to_string_sizes),
        cmocka_unit_test(test_error_codes),
        cmocka_unit_test(test_error_strings),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
