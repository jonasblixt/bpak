#include <string.h>
#include <bpak/bpak.h>
#include "nala.h"

TEST(header)
{
    struct bpak_header h;
    int rc;

    h.magic = 0;
    ASSERT_EQ(bpak_valid_header(&h), -BPAK_FAILED);

    rc = bpak_init_header(&h);

    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(bpak_valid_header(&h), BPAK_OK);
}

TEST(add_meta)
{
    struct bpak_header h;
    uint32_t *test = NULL;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &test, sizeof(test));
    ASSERT_EQ(rc, BPAK_OK);

    *test = 0x11223344;

    uint32_t *out = NULL;

    rc = bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(*out, 0x11223344);

    /* Try to get non-existing 'test-meta' after the first one */
    uint32_t *out2 = test; /* Begin search after the first meta*/

    rc = bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out2);
    ASSERT_EQ(rc, -BPAK_NOT_FOUND);
    ASSERT_EQ(out2, test);

    /* Add additional meta data with the same id */
    uint32_t *test2 = NULL;

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &test2, sizeof(test2));
    ASSERT_EQ(rc, BPAK_OK);
    *test2 = 0x55667788;

    uint32_t *out3 = test; /* Begin search after the first meta*/

    rc = bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out3);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(*out3, 0x55667788);
}

TEST(iterate_meta)
{
    struct bpak_header h;
    int rc;
    uint32_t *v = NULL;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    /* Data not populated yet */
    uint32_t *out = NULL;
    int c = 0;

    while (bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out) == BPAK_OK)
    {
        ASSERT_EQ(*out, 0x11223300 + c);
        c++;
    }

    for (int i = 0; i < 8; i++)
    {
        v = NULL;
        rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, sizeof(uint32_t));
        ASSERT_EQ(rc, BPAK_OK);

        (*v) = 0x11223300 + i;
    }

    while (bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out) == BPAK_OK)
    {
        ASSERT_EQ(*out, 0x11223300 + c);
        c++;
    }
}

TEST(too_many_meta_headers)
{
    struct bpak_header h;
    int rc;
    uint32_t *v = NULL;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    /* Fill all meta data headers*/
    for (int i = 0; i < BPAK_MAX_META; i++)
    {
        v = NULL;
        rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, sizeof(uint32_t));
        ASSERT_EQ(rc, BPAK_OK);
        ASSERT(v != NULL);
        (*v) = 0x11223300 + i;
    }

    uint32_t *out = NULL;
    int c = 0;
    while (bpak_get_meta(&h, bpak_id("test-meta"), (void **) &out) == BPAK_OK)
    {
        ASSERT_EQ(*out, 0x11223300 + c);
        c++;
    }

    v = NULL;
    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, sizeof(uint32_t));
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);

}

TEST(too_much_metadata)
{
    struct bpak_header h;
    int rc;
    uint32_t *v = NULL;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);


    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, BPAK_METADATA_BYTES);
    ASSERT_EQ(rc, BPAK_OK);

    /* metadata byte array is now full */

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, 1);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);


    /* Fill header array and meta data */
    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    v = NULL;
    for (int i = 0; i < BPAK_MAX_META; i++)
    {
        printf("%i\n", i);
        rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v,
                                            BPAK_METADATA_BYTES/BPAK_MAX_META);
        ASSERT_EQ(rc, BPAK_OK);
    }

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, (void **) &v, 1);
    ASSERT_EQ(rc, -BPAK_NO_SPACE_LEFT);
}
