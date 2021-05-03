/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_IO_H_
#define INCLUDE_BPAK_IO_H_

#include <bpak/bpak.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bpak_io_seek
{
    BPAK_IO_SEEK_SET,
    BPAK_IO_SEEK_FWD,
    BPAK_IO_SEEK_BACK,
    BPAK_IO_SEEK_END,
};

struct bpak_io;

typedef int (*on_bpak_close_t) (struct bpak_io *io);
typedef size_t (*on_bpak_io_t) (struct bpak_io *io, void *ptr, size_t size);
typedef int (*on_bpak_seek_t) (struct bpak_io *io, int64_t position);
typedef void (*on_bpak_flush_t) (struct bpak_io *io);

struct bpak_io
{
    uint64_t start_position;
    uint64_t end_position;
    uint64_t position;
    uint32_t alignment;
    void *priv;
    on_bpak_close_t on_close;
    on_bpak_io_t on_read;
    on_bpak_io_t on_write;
    on_bpak_seek_t on_seek;
    on_bpak_flush_t on_flush;
};


int bpak_io_init(struct bpak_io *io, void *priv);
size_t bpak_io_read(struct bpak_io *io, void *ptr, size_t size);
size_t bpak_io_write(struct bpak_io *io, const void *ptr, size_t size);
int bpak_io_seek(struct bpak_io *io, int64_t position,
                    enum bpak_io_seek seekop);
uint64_t bpak_io_tell(struct bpak_io *io);
int bpak_io_close(struct bpak_io *io);
void bpak_io_flush(struct bpak_io *io);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_IO_H_
