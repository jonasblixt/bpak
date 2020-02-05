#include <string.h>
#include <bpak/bpak.h>
#include "nala.h"

TEST(struct_sz)
{
    ASSERT_EQ(sizeof(struct bpak_header), 4096);
    ASSERT_EQ(sizeof(struct bpak_transport_meta), 32);
    ASSERT_EQ(sizeof(struct bpak_part_header), 32);
    ASSERT_EQ(sizeof(struct bpak_meta_header), 16);
}
