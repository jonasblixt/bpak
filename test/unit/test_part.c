#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "test_helpers.h"

static void test_part_header(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;
    h.magic = 0;
    assert_int_equal(bpak_valid_header(&h), -BPAK_BAD_MAGIC);

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p = NULL;

    rc = bpak_add_part(&h, bpak_id("test-part"), &p);
    assert_int_equal(rc, BPAK_OK);

    /* Try to retrive the same part */
    struct bpak_part_header *out = NULL;

    rc = bpak_get_part(&h, bpak_id("test-part"), &out);
    assert_int_equal(rc, BPAK_OK);
    assert_ptr_equal(out, p);
}

static void test_too_many_part_header(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p = NULL;

    for (int i = 0; i < BPAK_MAX_PARTS; i++) {
        rc = bpak_add_part(&h, bpak_id("test-part") + 1 + i, &p);
        assert_int_equal(rc, BPAK_OK);
    }

    rc = bpak_add_part(&h, bpak_id("test-part"), &p);
    assert_int_equal(rc, -BPAK_NO_SPACE_LEFT);
}

static void test_iterate_part_header(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p1 = NULL;
    struct bpak_part_header *p2 = NULL;
    struct bpak_part_header *p3 = NULL;

    rc = bpak_add_part(&h, bpak_id("test-part"), &p1);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part") + 1, &p2);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part") + 2, &p3);
    assert_int_equal(rc, BPAK_OK);

    struct bpak_part_header *out = NULL;

    rc = bpak_get_part(&h, bpak_id("test-part") + 2, &out);
    assert_int_equal(rc, BPAK_OK);
    assert_ptr_equal(out, p3);
}

static void test_delete_part(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p1 = NULL;
    struct bpak_part_header *p2 = NULL;
    struct bpak_part_header *p3 = NULL;

    rc = bpak_add_part(&h, bpak_id("test-part"), &p1);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part") + 1, &p2);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part") + 2, &p3);
    assert_int_equal(rc, BPAK_OK);

    bpak_del_part(&h, p2);

    struct bpak_part_header *out = NULL;
    rc = bpak_get_part(&h, bpak_id("test-part"), &out);
    assert_int_equal(rc, BPAK_OK);
    assert_ptr_equal(out, p1);

    rc = bpak_get_part(&h, bpak_id("test-part") + 1, &out);
    assert_int_equal(rc, -BPAK_NOT_FOUND);

    /* The remaining part is moved down to fill the hole */
    rc = bpak_get_part(&h, bpak_id("test-part") + 2, &out);
    assert_int_equal(rc, BPAK_OK);
    assert_true(out < p3);
}

static void test_delete_last_part(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p = NULL;

    for (int i = 0; i < BPAK_MAX_PARTS; i++) {
        rc = bpak_add_part(&h, bpak_id("test-part") + 1 + i, &p);
        assert_int_equal(rc, BPAK_OK);
    }

    bpak_del_part(&h, p);
    assert_int_equal(p->id, 0);
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_part_header),
        cmocka_unit_test(test_too_many_part_header),
        cmocka_unit_test(test_iterate_part_header),
        cmocka_unit_test(test_delete_part),
        cmocka_unit_test(test_delete_last_part),
        cmocka_unit_test(test_part_alignment),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
