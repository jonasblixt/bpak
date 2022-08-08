#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/utils.h>
#include "nala.h"

#define TEST_BFR_SZ 1024*16

static uint8_t test_buffer[TEST_BFR_SZ];

static uint32_t id(const char *s)
{
    return bpak_id(s);
}

static size_t test_write(struct bpak_io *io, void *ptr, size_t size)
{
    size_t s = size;

    if ((io->position + size) > io->end_position)
        s = io->end_position - io->position;

    memcpy(&test_buffer[io->position], ptr, s);
    io->position += size;
    return s;
}

static size_t test_read(struct bpak_io *io, void *ptr, size_t size)
{
    size_t s = size;

    if ((io->position + size) > io->end_position)
        s = io->end_position - io->position;

    memcpy(ptr, &test_buffer[io->position], s);

    io->position += size;
    return s;
}

TEST(io_init)
{
    int rc;
    struct bpak_io io;
    size_t s;

    rc = bpak_io_init(&io, NULL);
    ASSERT_EQ(rc, BPAK_OK);

    io.end_position = TEST_BFR_SZ;
    io.on_read = test_read;
    io.on_write = test_write;

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_init_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_write(&io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));
    ASSERT_EQ(bpak_io_tell(&io), sizeof(*h));

    /* Read 4kBytes without seeking first, should return invalid header */
    memset(h, 0, sizeof(*h));
    rc = bpak_io_read(&io, h, sizeof(*h));
    ASSERT_EQ(rc, sizeof(*h));
    rc  = bpak_valid_header(h);
    ASSERT_EQ(rc, -BPAK_BAD_MAGIC);

    /*  Seek to 0 and read header again*/
    memset(h, 0, sizeof(*h));
    rc = bpak_io_seek(&io, 0, BPAK_IO_SEEK_SET);
    ASSERT_EQ(rc, BPAK_OK);
    rc = bpak_io_read(&io, h, sizeof(*h));
    ASSERT_EQ(rc, sizeof(*h));
    rc  = bpak_valid_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    free(h);

    rc = bpak_io_close(&io);
    ASSERT_EQ(rc, BPAK_OK);
}

TEST(io_seek_back)
{
    int rc;
    struct bpak_io io;
    size_t s;

    rc = bpak_io_init(&io, NULL);
    ASSERT_EQ(rc, BPAK_OK);

    io.end_position = TEST_BFR_SZ;
    io.on_read = test_read;
    io.on_write = test_write;

    struct bpak_header *h = malloc(sizeof(struct bpak_header));
    memset(h, 0, sizeof(*h));

    rc = bpak_init_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_write(&io, h, sizeof(*h));
    ASSERT_EQ(s, sizeof(*h));
    ASSERT_EQ(bpak_io_tell(&io), sizeof(*h));

    memset(h, 0, sizeof(*h));
    rc = bpak_io_seek(&io, sizeof(*h), BPAK_IO_SEEK_BACK);
    ASSERT_EQ(rc, BPAK_OK);
    rc = bpak_io_read(&io, h, sizeof(*h));
    ASSERT_EQ(rc, sizeof(*h));
    rc  = bpak_valid_header(h);
    ASSERT_EQ(rc, BPAK_OK);

    free(h);

    const char *test_string = "Hejhopp";


    rc = bpak_io_seek(&io, strlen(test_string), BPAK_IO_SEEK_END);
    ASSERT_EQ(rc, BPAK_OK);

    s = bpak_io_write(&io, test_string, strlen(test_string));
    ASSERT_EQ(s, strlen(test_string));

    char read_back[16];

    rc = bpak_io_seek(&io, strlen(test_string), BPAK_IO_SEEK_END);
    ASSERT_EQ(rc, BPAK_OK);
    s = bpak_io_read(&io, read_back, strlen(test_string));
    ASSERT_EQ(s, strlen(test_string));
    ASSERT_MEMORY(read_back, test_string, strlen(test_string));

    rc = bpak_io_close(&io);
    ASSERT_EQ(rc, BPAK_OK);
}

TEST(io_seek_beyond_start_end)
{
    int rc;
    struct bpak_io io;
    size_t s;

    rc = bpak_io_init(&io, NULL);
    ASSERT_EQ(rc, BPAK_OK);

    io.end_position = TEST_BFR_SZ;
    io.on_read = test_read;
    io.on_write = test_write;

    rc = bpak_io_seek(&io, TEST_BFR_SZ, BPAK_IO_SEEK_FWD);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_io_seek(&io, 1, BPAK_IO_SEEK_FWD);
    ASSERT_EQ(rc, -BPAK_SEEK_ERROR);

    rc = bpak_io_seek(&io, 0, BPAK_IO_SEEK_SET);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_io_seek(&io, 1, BPAK_IO_SEEK_BACK);
    ASSERT_EQ(rc, -BPAK_SEEK_ERROR);
}

