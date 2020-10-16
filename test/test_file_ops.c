
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/file.h>
#include <bpak/utils.h>
#include "nala.h"

TEST(file_basic)
{
    int rc;
    struct bpak_io *io;
    size_t s;

    rc = bpak_io_init_file(&io, "/tmp/.bpak_test", "wb");
    ASSERT_EQ(rc, BPAK_OK);

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_init_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_write(io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));

    rc = bpak_io_close(io);
    ASSERT_EQ(rc, BPAK_OK);


    /* Close file and read back header */
    memset(h, 0, sizeof(*h));

    rc = bpak_io_init_file(&io, "/tmp/.bpak_test", "rb");
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_read(io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));

    rc = bpak_valid_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_io_close(io);
    ASSERT_EQ(rc, BPAK_OK);
    free(h);

}


TEST(file_part_write_part)
{
    int rc;
    struct bpak_io *io;
    size_t s;

    rc = bpak_io_init_file(&io, "/tmp/.bpak_test", "wb");
    ASSERT_EQ(rc, BPAK_OK);

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_init_header(h);
    ASSERT_EQ(rc, BPAK_OK);
    
    struct bpak_part_header *p;

    char *part_data = malloc(512);
    sprintf(part_data, "Hello part data");

    rc = bpak_add_part(h, bpak_id("test-tag"), &p);
    ASSERT_EQ(rc, BPAK_OK);
    p->size = 512;
    p->offset = 4096;

    char *part_data2 = malloc(512);
    sprintf(part_data2, "Hello part data2");

    rc = bpak_add_part(h, bpak_id("test-tag2"), &p);
    ASSERT_EQ(rc, BPAK_OK);
    p->size = 512;
    p->offset = 4096+512;

    uint32_t *meta_data = NULL;

    rc = bpak_add_meta(h, bpak_id("fancy-meta-data"), 0, (void **) &meta_data,
                            sizeof(*meta_data));
    ASSERT_EQ(rc, BPAK_OK);
    *meta_data = 0x11223344;

    s = bpak_io_write(io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));

    s = bpak_io_write(io, part_data, 512);
    ASSERT_EQ(s, 512);

    s = bpak_io_write(io, part_data2, 512);
    ASSERT_EQ(s, 512);

    rc = bpak_io_close(io);
    ASSERT_EQ(rc, BPAK_OK);

    free(part_data);
    free(part_data2);
    free(h);
}


TEST(file_part_read_part)
{
    int rc;
    struct bpak_io *io;
    size_t s;

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_io_init_file(&io, "/tmp/.bpak_test", "rb");
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_read(io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));

    rc = bpak_valid_header(h);
    ASSERT_EQ(rc, BPAK_OK);
    
    struct bpak_part_header *p = NULL;
    rc = bpak_get_part(h, bpak_id("test-tag"), &p);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_get_part(h, bpak_id("missing-tag"), &p);
    ASSERT_EQ(rc, -BPAK_NOT_FOUND);

    uint32_t *meta_data = NULL;

    rc = bpak_get_meta(h, bpak_id("fancy-meta-data"), (void **) &meta_data);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_EQ(*meta_data, 0x11223344);
    
    char *part_data = malloc(512);
    s = bpak_io_read(io, part_data, 512);
    ASSERT_EQ(s, 512);
    ASSERT_MEMORY(part_data, "Hello part data", 16);

    s = bpak_io_read(io, part_data, 512);
    ASSERT_EQ(s, 512);
    ASSERT_MEMORY(part_data, "Hello part data2", 17);

    rc = bpak_io_close(io);
    ASSERT_EQ(rc, BPAK_OK);
    free(part_data);
    free(h);
}


TEST(file_seek_part)
{
    int rc;
    struct bpak_io *io;
    size_t s;

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_io_init_file(&io, "/tmp/.bpak_test", "rb");
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_read(io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));

    rc = bpak_valid_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    struct bpak_part_header *p = NULL;

    rc = bpak_get_part(h, bpak_id("test-tag2"), &p);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_io_seek(io, p->offset, BPAK_IO_SEEK_SET);
    ASSERT_EQ(rc, BPAK_OK);

    char *buf = malloc(512);

    s = bpak_io_read(io, buf, 512);
    ASSERT_EQ(s, 512);

    ASSERT_MEMORY(buf, "Hello part data2", 17);

    rc = bpak_io_close(io);
    ASSERT_EQ(rc, BPAK_OK);
    free(buf);
    free(h);   
}
