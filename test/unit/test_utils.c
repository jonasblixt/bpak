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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bin2hex),
        cmocka_unit_test(test_bin2hex_buffer_too_small),
        cmocka_unit_test(test_hash_tree_id),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
