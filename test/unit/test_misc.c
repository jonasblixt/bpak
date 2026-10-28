#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
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

static void test_struct_sz(void **state)
{
    (void)state;
    assert_int_equal(sizeof(struct bpak_header), 4096);
    assert_int_equal(sizeof(struct bpak_transport_meta), 32);
    assert_int_equal(sizeof(struct bpak_part_header), 32);
    assert_int_equal(sizeof(struct bpak_meta_header), 16);
}

static void test_part_alignment(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    struct bpak_part_header *p;

    rc = bpak_add_part(&h, bpak_id("part-with-bad-alignment"), &p);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, BPAK_OK);

    p->offset = 0;
    p->size = 513;

    /*   rc = bpak_valid_header(&h);
       assert_int_equal(rc, -BPAK_BAD_ALIGNMENT);*/
}

static void check_ptr_alignment(void *p)
{
    assert_int_equal(((uintptr_t)p) % 8, 0);
}

static void test_meta_align(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_meta_header *meta;
    const size_t sizes[] = {8, 4, 2, 1, 8};
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        rc = bpak_add_meta(&h, bpak_id("test-meta") + i, 0, sizes[i], &meta);
        assert_int_equal(rc, BPAK_OK);
        check_ptr_alignment(bpak_get_meta_ptr(&h, meta, void));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_error_codes),
        cmocka_unit_test(test_struct_sz),
        cmocka_unit_test(test_part_alignment),
        cmocka_unit_test(test_meta_align),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
