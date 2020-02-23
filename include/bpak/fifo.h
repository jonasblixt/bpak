#ifndef INCLUDE_BPAK_FIFO_H_
#define INCLUDE_BPAK_FIFO_H_

#include <stdint.h>
#include <bpak/bpak.h>
#include <bpak/io.h>

struct bpak_io_fifo
{
    uint64_t head;
    uint64_t tail;
    uint8_t *buffer;
    size_t buffer_size;
};

#define GET_FIFO_CTX(__io) ((struct bpak_io_fifo *) __io->priv)

int bpak_io_fifo_init(struct bpak_io **_io, size_t size);
size_t bpak_fifo_available_space(struct bpak_io *io);
size_t bpak_fifo_available_data(struct bpak_io *io);

#endif  // INCLUDE_BPAK_FIFO_H_
