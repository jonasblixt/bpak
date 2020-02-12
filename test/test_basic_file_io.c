#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/file.h>
#include "nala.h"

TEST(invalid_file)
{
    struct bpak_io *io = NULL;
    int rc;

    rc = bpak_io_init_file(&io, "does_not_EXIST", "rb");

    printf("rc = %i\n", rc);

    ASSERT(rc != BPAK_OK);
}

TEST(invalid_mode)
{
    struct bpak_io *io = NULL;
    int rc;

    rc = bpak_io_init_file(&io, "invalid_mode_test.txt", "");

    printf("rc = %i\n", rc);

    ASSERT(rc != BPAK_OK);
}

TEST(invalid_file2)
{
    struct bpak_io *io = NULL;
    int rc;

    rc = bpak_io_init_file(&io, "(null)", "(null)");

    printf("rc = %i\n", rc);

    ASSERT(rc != BPAK_OK);
}
