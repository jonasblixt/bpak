#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "test_helpers.h"

static int add_meta_uint32_t(struct bpak_header *header, bpak_id_t id,
    bpak_id_t part_ref, uint32_t value)
{
    struct bpak_meta_header *meta;
    int rc;

    rc = bpak_add_meta(header, id, part_ref, sizeof(uint32_t), &meta);
    if (rc != BPAK_OK) {
        return rc;
    }

    *bpak_get_meta_ptr(header, meta, uint32_t) = value;

    return rc;
}

static int get_meta_uint32_t(struct bpak_header *header, bpak_id_t id,
    bpak_id_t part_ref, uint32_t *value)
{
    struct bpak_meta_header *meta;
    int rc;

    rc = bpak_get_meta(header, id, part_ref, &meta);
    if (rc != BPAK_OK) {
        return rc;
    }

    *value = *bpak_get_meta_ptr(header, meta, uint32_t);

    return rc;
}

static void test_header(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    h.magic = 0;
    assert_int_equal(bpak_valid_header(&h), -BPAK_BAD_MAGIC);

    rc = bpak_init_header(&h);

    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(bpak_valid_header(&h), BPAK_OK);
}

static void test_add_meta(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0,
                           0x11223344);
    assert_int_equal(rc, BPAK_OK);

    uint32_t out = 0;

    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0, &out);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(out, 0x11223344);

    /* Add additional meta data with the same id */
    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           1,
                           0x55667788);
    assert_int_equal(rc, BPAK_OK);

    /* Begin search after the first meta */
    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x1, &out);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(out, 0x55667788);
}

static void test_too_many_meta_headers(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    /* Fill all meta data headers*/
    for (int i = 0; i < BPAK_MAX_META; i++) {
        rc = add_meta_uint32_t(&h,
                               bpak_id("test-meta"),
                               i,
                               0x11223300 + i);
        assert_int_equal(rc, BPAK_OK);
    }

    uint32_t out = 0;
    int c = 0;

    bpak_foreach_meta(&h, m) {
        if (!m->id)
            break;

        out = *bpak_get_meta_ptr(&h, m, uint32_t);
        assert_int_equal(out, 0x11223300 + c);
        c++;
    }

    assert_int_equal(c, BPAK_MAX_META);

    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x30,
                           0x00);
    assert_int_equal(rc, -BPAK_NO_SPACE_LEFT);
}

static void test_too_much_metadata(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_meta_header *meta;
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_add_meta(&h,
                       bpak_id("test-meta"),
                       0,
                       BPAK_METADATA_BYTES,
                       &meta);
    assert_int_equal(rc, BPAK_OK);

    /* metadata byte array is now full */
    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0x1, 1, &meta);
    assert_int_equal(rc, -BPAK_NO_SPACE_LEFT);

    /* A failed add leaves no meta data entry behind */
    assert_int_equal(h.meta[1].id, 0);
    assert_int_equal(h.meta[1].offset, 0);
    assert_int_equal(h.meta[1].size, 0);
    assert_int_equal(h.meta[1].part_id_ref, 0);

    /* Fill header array and meta data */
    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    for (int i = 0; i < 30; i++) {
        rc = bpak_add_meta(&h, bpak_id("test-meta"), i, 64, &meta);
        assert_int_equal(rc, BPAK_OK);
    }

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0x100, 1, &meta);
    assert_int_equal(rc, -BPAK_NO_SPACE_LEFT);
}

static void test_delete_meta(void **state)
{
    (void)state;
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    assert_int_equal(rc, BPAK_OK);

    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x1,
                           0x11223344);
    assert_int_equal(rc, BPAK_OK);

    uint32_t out = 0;

    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x1, &out);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(out, 0x11223344);

    /* Add additional meta data with the same id */
    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x2,
                           0x55667788);
    assert_int_equal(rc, BPAK_OK);

    uint32_t out2 = 0;

    /* Begin search after the second meta */
    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x2, &out2);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(out2, 0x55667788);

    /* Delete the first part */
    struct bpak_meta_header *meta;

    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x1, &meta);
    assert_int_equal(rc, BPAK_OK);
    out = *bpak_get_meta_ptr(&h, meta, uint32_t);
    assert_int_equal(out, 0x11223344);

    bpak_del_meta(&h, meta);

    /* Verify it is gone, and that second meta can still be read */
    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x1, &meta);
    assert_int_equal(rc, -BPAK_NOT_FOUND);

    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x2, &meta);
    assert_int_equal(rc, BPAK_OK);
    out = *bpak_get_meta_ptr(&h, meta, uint32_t);
    assert_int_equal(out, 0x55667788);
}

static void test_meta_bad_layout(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_meta_header *meta;
    int rc;

    /* Lookups search all slots, meta data after an empty slot is rejected */
    bpak_init_header(&h);
    h.meta[1].id = bpak_id("test-meta");
    h.meta[1].offset = 1900;
    h.meta[1].size = 0xffff;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_NOT_SUPPORTED);

    /* Values are aligned */
    bpak_init_header(&h);
    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, 4, &meta);
    assert_int_equal(rc, BPAK_OK);
    meta->offset = 4;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_BAD_ALIGNMENT);

    meta->offset = BPAK_METADATA_BYTES - 8;
    meta->size = 9;

    rc = bpak_valid_header(&h);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    /* Id 0 is an empty slot, not meta data */
    rc = bpak_get_meta(&h, 0, 0, &meta);
    assert_int_equal(rc, -BPAK_NOT_FOUND);
    rc = bpak_get_meta_anyref(&h, 0, &meta);
    assert_int_equal(rc, -BPAK_NOT_FOUND);
}

/* Header with a part and meta data i of 'sizes[i]' bytes filled with i + 1,
 * leaving out 'skip' */
static void build_header(struct bpak_header *h, const uint16_t *sizes, size_t n,
                         size_t skip)
{
    struct bpak_part_header *part;
    struct bpak_meta_header *meta;
    int rc;

    bpak_init_header(h);
    rc = bpak_add_part(h, bpak_id("test-part"), &part);
    assert_int_equal(rc, BPAK_OK);
    part->size = 512;

    for (size_t i = 0; i < n; i++) {
        if (i == skip)
            continue;

        rc = bpak_add_meta(h, i + 1, 0, sizes[i], &meta);
        assert_int_equal(rc, BPAK_OK);
        memset(bpak_get_meta_ptr(h, meta, uint8_t), i + 1, sizes[i]);
    }
}

/* Deleting meta data must give the header without it */
static void check_delete_meta(const uint16_t *sizes, size_t n, size_t index)
{
    struct bpak_header h, expected;
    struct bpak_meta_header *meta;
    int rc;

    build_header(&h, sizes, n, n);
    build_header(&expected, sizes, n, index);

    rc = bpak_get_meta(&h, index + 1, 0, &meta);
    assert_int_equal(rc, BPAK_OK);
    bpak_del_meta(&h, meta);

    assert_memory_equal(&h, &expected, sizeof(h));
}

static void test_delete_meta_layout(void **state)
{
    (void)state;
    const uint16_t sizes[] = { 8, 16, 3, 8, 32, 1 };
    const size_t n = sizeof(sizes) / sizeof(sizes[0]);

    for (size_t i = 0; i < n; i++)
        check_delete_meta(sizes, n, i);
}

static void test_delete_meta_full(void **state)
{
    (void)state;
    uint16_t sizes[BPAK_MAX_META];

    for (size_t i = 0; i < BPAK_MAX_META; i++)
        sizes[i] = 8 + (i % 3) * 4;

    check_delete_meta(sizes, BPAK_MAX_META, 0);
    check_delete_meta(sizes, BPAK_MAX_META, 5);
    check_delete_meta(sizes, BPAK_MAX_META, BPAK_MAX_META - 1);
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
        cmocka_unit_test(test_header),
        cmocka_unit_test(test_add_meta),
        cmocka_unit_test(test_too_many_meta_headers),
        cmocka_unit_test(test_too_much_metadata),
        cmocka_unit_test(test_delete_meta),
        cmocka_unit_test(test_delete_meta_layout),
        cmocka_unit_test(test_delete_meta_full),
        cmocka_unit_test(test_meta_bad_layout),
        cmocka_unit_test(test_meta_align),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
