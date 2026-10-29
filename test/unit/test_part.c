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

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_BAD_ALIGNMENT);

    /* Padding of a whole alignment block */
    p->size = 512;
    p->pad_bytes = 512;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_BAD_ALIGNMENT);
}

static void test_part_empty_slot(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_part_header *p;
    int rc;

    bpak_init_header(&h);

    /* Lookups search all slots, a part after an empty slot is rejected */
    h.parts[1].id = bpak_id("test-part");
    h.parts[1].size = 512;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_NOT_SUPPORTED);

    /* Id 0 is an empty slot, not a part */
    bpak_init_header(&h);

    rc = bpak_get_part(&h, 0, &p);
    assert_int_equal(rc, -BPAK_NOT_FOUND);
}

static void test_part_size_overflow(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_part_header *p;
    int rc;

    bpak_init_header(&h);

    rc = bpak_add_part(&h, bpak_id("test-part"), &p);
    assert_int_equal(rc, BPAK_OK);

    /* size + pad_bytes wraps around to 0 */
    p->size = UINT64_MAX - 7;
    p->pad_bytes = 8;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    /* Does not fit off_t */
    p->size = (uint64_t)1 << 63;
    p->pad_bytes = 0;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    p->size = 512;
    p->flags = BPAK_FLAG_TRANSPORT;
    p->transport_size = UINT64_MAX;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    /* Each part fits, the offset of the second does not */
    p->flags = 0;
    p->transport_size = 0;
    p->size = (uint64_t)1 << 62;

    rc = bpak_add_part(&h, bpak_id("test-part2"), &p);
    assert_int_equal(rc, BPAK_OK);
    p->size = (uint64_t)1 << 62;

    if (sizeof(off_t) == 8) {
        rc = bpak_valid_header(&h);
        assert_int_equal(rc, -BPAK_SIZE_ERROR);
    }

    p->size = 512;

    if (sizeof(size_t) == 8) {
        rc = bpak_valid_header(&h);
        assert_int_equal(rc, BPAK_OK);
    }
}

static void test_signature_size(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    bpak_init_header(&h);

    h.signature_sz = sizeof(h.signature);
    rc = bpak_valid_header(&h);
    assert_int_equal(rc, BPAK_OK);

    /* Not covered by the header hash */
    h.signature_sz = sizeof(h.signature) + 1;
    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
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
        cmocka_unit_test(test_part_empty_slot),
        cmocka_unit_test(test_part_size_overflow),
        cmocka_unit_test(test_signature_size),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
