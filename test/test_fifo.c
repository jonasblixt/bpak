#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/fifo.h>
#include "nala.h"

TEST(create_fifo)
{
    int rc;
    struct bpak_io *f = NULL;

    rc = bpak_io_fifo_init(&f, 16);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_io_close(f);
    ASSERT_EQ(rc, BPAK_OK);
}

TEST(fifo_write1)
{
    int rc;
    struct bpak_io *f = NULL;
    struct bpak_io_fifo *fifo_p;
    char bfr[16];
    size_t bytes = 0;


    memset(bfr, 0, sizeof(bfr));

    rc = bpak_io_fifo_init(&f, 16);
    ASSERT_EQ(rc, BPAK_OK);

    bytes = bpak_io_write(f, "Hello", 5);
    ASSERT_EQ(bytes, 5);

    fifo_p = GET_FIFO_CTX(f);
    ASSERT_EQ(fifo_p->head, 5);

    bytes = bpak_io_read(f, bfr, sizeof(bfr));
    ASSERT_EQ(bytes, 5);
    ASSERT_EQ((char *) bfr, "Hello");
    ASSERT_EQ(fifo_p->tail, 5);

    rc = bpak_io_close(f);
    ASSERT_EQ(rc, BPAK_OK);
}

/*
 *
 * Bfr 01234567
 *
 * W1  Hello
 *     t    h
 *
 * R1       t
 *          h
 * Bfr 01234567
 *
 * W2  lo   Hel
 *       h  t
 */

TEST(fifo_write_overlap)
{
    int rc;
    struct bpak_io *f = NULL;
    struct bpak_io_fifo *fifo_p;
    char bfr[16];
    size_t bytes = 0;


    memset(bfr, 0, sizeof(bfr));

    rc = bpak_io_fifo_init(&f, 8);
    ASSERT_EQ(rc, BPAK_OK);

    bytes = bpak_io_write(f, "Hello", 5);
    ASSERT_EQ(bytes, 5);

    fifo_p = GET_FIFO_CTX(f);
    ASSERT_EQ(fifo_p->head, 5);

    bytes = bpak_io_read(f, bfr, sizeof(bfr));
    ASSERT_EQ(bytes, 5);
    ASSERT_EQ((char *) bfr, "Hello");
    ASSERT_EQ(fifo_p->tail, 5);


    memset(bfr, 0, sizeof(bfr));

    bytes = bpak_io_write(f, "Hello", 5);
    ASSERT_EQ(bytes, 5);

    fifo_p = GET_FIFO_CTX(f);
    ASSERT_EQ(fifo_p->head, 3);
    ASSERT_EQ(fifo_p->tail, 5);

    bytes = bpak_io_read(f, bfr, sizeof(bfr));
    ASSERT_EQ(bytes, 5);
    ASSERT_EQ((char *) bfr, "Hello");
    ASSERT_EQ(fifo_p->tail, 3);
    ASSERT_EQ(fifo_p->head, 3);

    rc = bpak_io_close(f);
    ASSERT_EQ(rc, BPAK_OK);
}
