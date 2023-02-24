#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "nala.h"

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

TEST(header)
{
    struct bpak_header h;
    int rc;

    h.magic = 0;
    ASSERT_EQ(bpak_valid_header(&h), -BPAK_BAD_MAGIC);

    rc = bpak_init_header(&h);

    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(bpak_valid_header(&h), BPAK_OK);
}

TEST(add_meta)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0,
                           0x11223344);
    ASSERT_EQ(rc, BPAK_OK);

    uint32_t out = 0;

    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0, &out);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(out, 0x11223344);

    /* Add additional meta data with the same id */
    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           1,
                           0x55667788);
    ASSERT_EQ(rc, BPAK_OK);

    /* Begin search after the first meta */
    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x1, &out);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(out, 0x55667788);
}

TEST(too_many_meta_headers)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    /* Fill all meta data headers*/
    for (int i = 0; i < BPAK_MAX_META; i++) {
        rc = add_meta_uint32_t(&h,
                               bpak_id("test-meta"),
                               i,
                               0x11223300 + i);
        ASSERT_EQ(rc, BPAK_OK);
    }

    uint32_t out = 0;
    int c = 0;

    bpak_foreach_meta(&h, m) {
        if (!m->id)
            break;

        out = *bpak_get_meta_ptr(&h, m, uint32_t);
        ASSERT_EQ(out, 0x11223300 + c);
        c++;
    }


    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x30,
                           0x00);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);
}

TEST(too_much_metadata)
{
    struct bpak_header h;
    struct bpak_meta_header *meta;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_meta(&h,
                       bpak_id("test-meta"),
                       0,
                       BPAK_METADATA_BYTES,
                       &meta);
    ASSERT_EQ(rc, BPAK_OK);

    /* metadata byte array is now full */
    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0x1, 1, &meta);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);

    /* Fill header array and meta data */
    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    for (int i = 0; i < 30; i++) {
        // printf("%i\n", i);
        rc = bpak_add_meta(&h, bpak_id("test-meta"), i, 64, &meta);
        // printf("meta %p\n", meta);
        ASSERT_EQ(rc, BPAK_OK);
    }

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0x100, 1, &meta);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);
}

TEST(delete_meta)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x1,
                           0x11223344);
    ASSERT_EQ(rc, BPAK_OK);

    uint32_t out = 0;

    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x1, &out);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(out, 0x11223344);

    /* Add additional meta data with the same id */
    rc = add_meta_uint32_t(&h,
                           bpak_id("test-meta"),
                           0x2,
                           0x55667788);
    ASSERT_EQ(rc, BPAK_OK);

    uint32_t out2 = 0;

    /* Begin search after the second meta */
    rc = get_meta_uint32_t(&h, bpak_id("test-meta"), 0x2, &out2);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(out2, 0x55667788);

    /* Delete the first part */
    struct bpak_meta_header *meta;

    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x1, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    out = *bpak_get_meta_ptr(&h, meta, uint32_t);
    ASSERT_EQ(out, 0x11223344);

    bpak_del_meta(&h, meta);

    /* Verify it is gone, and that second meta can still be read */
    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x1, &meta);
    ASSERT_EQ(rc, -BPAK_NOT_FOUND);

    rc = bpak_get_meta(&h, bpak_id("test-meta"), 0x2, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    out = *bpak_get_meta_ptr(&h, meta, uint32_t);
    ASSERT_EQ(out, 0x55667788);
}
