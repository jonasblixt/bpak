#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "nala.h"

TEST(part_alignment)
{
    struct bpak_header h;
    int rc;

    rc = bpak_init_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    struct bpak_part_header *p;

    rc = bpak_add_part(&h, bpak_id("part-with-bad-alignment"), &p);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_valid_header(&h);
    ASSERT_EQ(rc, BPAK_OK);

    p->offset = 0;
    p->size = 513;

 /*   rc = bpak_valid_header(&h);
    ASSERT_EQ(rc, -BPAK_BAD_ALIGNMENT);*/
}
