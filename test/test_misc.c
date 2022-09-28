#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include "nala.h"

TEST(error_codes)
{
    unsigned int end = BPAK_KEY_NOT_FOUND;

    for (unsigned int i = 0; i < end; i++) {
        ASSERT(bpak_error_string(-i) != bpak_error_string(1));
    }

    printf("%s %s\n", bpak_error_string(end + 1), bpak_error_string(1));
    ASSERT(bpak_error_string(end + 1) == bpak_error_string(1));
}
