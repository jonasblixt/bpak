#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "nala.h"

void test_ptr_alignment(void *p)
{
    printf("Checking pointer %p\n", p);
    ASSERT_EQ(((uintptr_t)p) % 8, 0);
}

TEST(meta_align)
{
    struct bpak_header h;
    struct bpak_meta_header *meta;
    void *p = NULL;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_meta(&h, bpak_id("test-meta1"), 0, 8, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    p = bpak_get_meta_ptr(&h, meta, void);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta2"), 0, 4, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    p = bpak_get_meta_ptr(&h, meta, void);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta3"), 0, 2, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    p = bpak_get_meta_ptr(&h, meta, void);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta4"), 0, 1, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    p = bpak_get_meta_ptr(&h, meta, void);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta5"), 0, 8, &meta);
    ASSERT_EQ(rc, BPAK_OK);
    p = bpak_get_meta_ptr(&h, meta, void);
    test_ptr_alignment(p);
}
