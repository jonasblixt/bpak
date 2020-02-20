/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/io.h>


int bpak_io_init(struct bpak_io *io, void *priv)
{
    memset(io, 0, sizeof(*io));

    io->priv = priv;
    io->alignment = 1;

    return BPAK_OK;
}

size_t bpak_io_read(struct bpak_io *io, void *ptr, size_t size)
{
    size_t read_bytes = 0;

    if ((size % io->alignment) != 0)
        return 0;

    read_bytes = io->on_read(io, ptr, size);

    return read_bytes;
}

size_t bpak_io_write(struct bpak_io *io, const void *ptr, size_t size)
{
    size_t written_bytes = 0;

    if ((size % io->alignment) != 0)
        return -BPAK_BAD_ALIGNMENT;

    written_bytes = io->on_write(io, (void *) ptr, size);
    return written_bytes;
}

int bpak_io_seek(struct bpak_io *io, int64_t position,
                    enum bpak_io_seek seekop)
{
    uint64_t new_position;

    switch (seekop)
    {
        case BPAK_IO_SEEK_SET:
            new_position = io->start_position + position;
        break;
        case BPAK_IO_SEEK_FWD:
            new_position = io->position + position;
        break;
        case BPAK_IO_SEEK_BACK:
            new_position = io->position - position;
        break;
        case BPAK_IO_SEEK_END:
            new_position = io->end_position - position;
        break;
        default:
            return -BPAK_FAILED;
    }

    /* Check alignment of new position */

    if ((new_position % io->alignment) != 0)
        return -BPAK_BAD_ALIGNMENT;

    /* Check seek boundaries */
    if ( (new_position < io->start_position) ||
         (new_position > io->end_position))
    {
        return -BPAK_SEEK_ERROR;
    }

    if (io->on_seek)
    {
        if (io->on_seek(io, new_position) != BPAK_OK)
            return -BPAK_FAILED;
    }

    io->position = new_position;

    return BPAK_OK;
}

uint64_t bpak_io_tell(struct bpak_io *io)
{
    return io->position;
}

int bpak_io_close(struct bpak_io *io)
{
    int rc = BPAK_OK;

    if (io->on_close)
        rc = io->on_close(io);

    return rc;
}

