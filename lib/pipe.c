#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/pipe.h>


#define GET_PIPE_CTX(__io) ((struct bpak_io_pipe_ctx *) __io->priv)

struct bpak_io_pipe_ctx
{
    int fds[2];
    struct bpak_io_ops *ops;
};

static int bpak_io_pipe_cleanup(struct bpak_io *io)
{
    struct bpak_io_pipe_ctx *ctx = GET_PIPE_CTX(io);
    close(ctx->fds[0]);
    close(ctx->fds[1]);
    free(ctx);
    free(io);
    return BPAK_OK;
}

static size_t bpak_io_pipe_write(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_pipe_ctx *ctx = GET_PIPE_CTX(io);
    return write(ctx->fds[1], ptr, size);
}


static size_t bpak_io_pipe_read(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_pipe_ctx *ctx = GET_PIPE_CTX(io);
    return read(ctx->fds[0], ptr, size);
}

int bpak_io_init_pipe(struct bpak_io **io_)
{
    int rc = BPAK_OK;

    *io_ = malloc(sizeof(struct bpak_io));

    struct bpak_io *io = *io_;

    if (!io)
        return -BPAK_FAILED;

    struct bpak_io_pipe_ctx *ctx = malloc(sizeof(struct bpak_io_pipe_ctx));

    if (!ctx)
    {
        rc = -BPAK_FAILED;
        goto err_free_io_out;
    }

    memset(ctx, 0, sizeof(struct bpak_io_pipe_ctx));

    rc = bpak_io_init(io, ctx);

    if (rc != BPAK_OK)
        goto err_free_ctx_out;

    rc = pipe(ctx->fds);

    if (fcntl(ctx->fds[0], F_SETFL, O_NONBLOCK) < 0)
    {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    if (fcntl(ctx->fds[1], F_SETFL, O_NONBLOCK) < 0)
    {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    if (rc != 0)
    {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    io->end_position = -1;
    io->on_write = bpak_io_pipe_write;
    io->on_read = bpak_io_pipe_read;
    io->on_seek = NULL;
    io->on_close = bpak_io_pipe_cleanup;

    return rc;
err_free_ctx_out:
    free(io->priv);
err_free_io_out:
    free(io);
    return rc;
}
