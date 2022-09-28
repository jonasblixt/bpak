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
    void *p = NULL;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, &p, 8);
    ASSERT_EQ(rc, BPAK_OK);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, &p, 4);
    ASSERT_EQ(rc, BPAK_OK);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, &p, 2);
    ASSERT_EQ(rc, BPAK_OK);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, &p, 1);
    ASSERT_EQ(rc, BPAK_OK);
    test_ptr_alignment(p);

    rc = bpak_add_meta(&h, bpak_id("test-meta"), 0, &p, 8);
    ASSERT_EQ(rc, BPAK_OK);
    test_ptr_alignment(p);
}
