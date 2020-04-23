#include <string.h>
#include <stdlib.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/fifo.h>

size_t bpak_fifo_available_space(struct bpak_io *io)
{
    struct bpak_io_fifo *ctx = GET_FIFO_CTX(io);
    return (ctx->buffer_size - ctx->buffer_count);
}

size_t bpak_fifo_available_data(struct bpak_io *io)
{
    struct bpak_io_fifo *ctx = GET_FIFO_CTX(io);
    return ctx->buffer_count;
}

static int bpak_io_fifo_cleanup(struct bpak_io *io)
{
    struct bpak_io_fifo *ctx = GET_FIFO_CTX(io);
    free(ctx->buffer);
    free(ctx);
    free(io);
    return BPAK_OK;
}

static size_t bpak_io_fifo_write(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_fifo *ctx = GET_FIFO_CTX(io);
    size_t avail_space = ctx->buffer_size - ctx->buffer_count;
    size_t write_bytes = (size > avail_space)?avail_space:size;

    if (!write_bytes)
        return 0;

    if (write_bytes > (ctx->buffer_size - ctx->head))
    {
        size_t chunk = ctx->buffer_size - ctx->head;
        uint8_t *chunk_p = (uint8_t *) ptr;
        chunk_p += chunk;

        memcpy(&ctx->buffer[ctx->head], ptr, chunk);
        memcpy(ctx->buffer, chunk_p, write_bytes - chunk);
        ctx->head = write_bytes - chunk;
    }
    else
    {
        memcpy(&ctx->buffer[ctx->head], ptr, write_bytes);
        ctx->head += write_bytes;
    }

    ctx->buffer_count += write_bytes;
    return write_bytes;
}

static size_t bpak_io_fifo_read(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_fifo *ctx = GET_FIFO_CTX(io);

    size_t available_bytes = ctx->buffer_count;
    size_t bytes_to_read = size > available_bytes?available_bytes:size;

    if (!available_bytes)
        return 0;

    if (ctx->head > ctx->tail)
    {
        memcpy((uint8_t *) ptr, (uint8_t *) &ctx->buffer[ctx->tail],
                                    bytes_to_read);
        ctx->tail += bytes_to_read;
        ctx->buffer_count -= bytes_to_read;
    }
    else /* Wrapped around, tail is before head */
    {
        size_t first_chunk = (ctx->buffer_size - ctx->tail);
        size_t chunk = (bytes_to_read > first_chunk)?first_chunk:bytes_to_read;
        size_t remainder = bytes_to_read;

        uint8_t *first_chunk_p = (uint8_t *) ptr;
        memcpy(first_chunk_p, (uint8_t *) &ctx->buffer[ctx->tail], chunk);
        ctx->tail = (ctx->tail + chunk) % ctx->buffer_size;
        ctx->buffer_count -= chunk;
        remainder -= chunk;

        if (remainder)
        {
            uint8_t *second_chunk_p = ((uint8_t *) ptr) + first_chunk;
            memcpy(second_chunk_p, (uint8_t *) ctx->buffer, remainder);
            ctx->tail = remainder;
            ctx->buffer_count -= remainder;
        }

    }

    return bytes_to_read;
}

int bpak_io_fifo_init(struct bpak_io **_io, size_t size)
{
    int rc;
    *_io = malloc(sizeof(struct bpak_io));

    struct bpak_io *io = *_io;

    if (!io)
        return -BPAK_FAILED;

    struct bpak_io_fifo *ctx = malloc(sizeof(struct bpak_io_fifo));

    if (!ctx)
    {
        rc = -BPAK_FAILED;
        goto err_free_io_out;
    }

    memset(ctx, 0, sizeof(struct bpak_io_fifo));

    ctx->buffer = malloc(size);
    ctx->buffer_size = size;
    ctx->buffer_count = 0;

    if (!ctx->buffer)
    {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    rc = bpak_io_init(io, ctx);

    if (rc != BPAK_OK)
        goto err_free_buffer_out;


    io->on_write = bpak_io_fifo_write;
    io->on_read = bpak_io_fifo_read;
    io->on_seek = NULL;
    io->on_close = bpak_io_fifo_cleanup;

    return BPAK_OK;
err_free_buffer_out:
    free(ctx->buffer);
err_free_ctx_out:
    free(ctx);
err_free_io_out:
    free(io);
    return rc;
}
