#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "nala.h"

TEST(part_header)
{
    struct bpak_header h;
    int rc;
    h.magic = 0;
    ASSERT_EQ(bpak_valid_header(&h), -BPAK_BAD_MAGIC);

    rc = bpak_init_header(&h);

    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p = NULL;

    rc = bpak_add_part(&h, bpak_id("test-part"), &p);
    ASSERT_EQ(rc, BPAK_OK);

    /* Try to retrive the same part */
    struct bpak_part_header *out = NULL;

    rc = bpak_get_part(&h, bpak_id("test-part"), &out, NULL);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT(out == p);
}

TEST(too_many_part_header)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p = NULL;

    for (int i = 0; i < BPAK_MAX_PARTS; i++) {
        rc = bpak_add_part(&h, bpak_id("test-part"), &p);
        ASSERT_EQ(rc, BPAK_OK);
    }

    rc = bpak_add_part(&h, bpak_id("test-part"), &p);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);
}

TEST(error_strings)
{
    ASSERT_EQ(bpak_error_string(BPAK_OK), "OK");
    ASSERT_EQ(bpak_error_string(-BPAK_FAILED), "Failed");
    ASSERT_EQ(bpak_error_string(-BPAK_NOT_FOUND), "Not found");
    ASSERT_EQ(bpak_error_string(-BPAK_SIZE_ERROR), "Size error");
    ASSERT_EQ(bpak_error_string(-BPAK_NO_SPACE_LEFT), "No space left");
    ASSERT_EQ(bpak_error_string(-BPAK_BAD_ALIGNMENT), "Bad alignment");
    ASSERT_EQ(bpak_error_string(-BPAK_SEEK_ERROR), "Seek error");
    ASSERT_EQ(bpak_error_string(-BPAK_NOT_SUPPORTED), "Not supported");
    ASSERT_EQ(bpak_error_string(-999999), "Unknown");
}

TEST(iterate_part_header)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);

    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(bpak_valid_header(&h), BPAK_OK);

    struct bpak_part_header *p1 = NULL;
    struct bpak_part_header *p2 = NULL;
    struct bpak_part_header *p3 = NULL;

    rc = bpak_add_part(&h, bpak_id("test-part"), &p1);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part"), &p2);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_part(&h, bpak_id("test-part"), &p3);
    ASSERT_EQ(rc, BPAK_OK);

    struct bpak_part_header *out = NULL;

    rc = bpak_get_part(&h, bpak_id("test-part"), &out, p2);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(out, p3);
}
