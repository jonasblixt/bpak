/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/file.h>

#define GET_FILE_CTX(__io) ((struct bpak_io_file_ctx *) __io->priv)

struct bpak_io_file_ctx
{
    FILE *fp;
    struct bpak_io_ops *ops;
    struct bpak_header *header;
    const char *filename;
    bool remove_on_close;
};

static int bpak_io_file_cleanup(struct bpak_io *io)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);
    fclose(ctx->fp);

    if (ctx->remove_on_close)
        remove(ctx->filename);

    free((void *) ctx->filename);
    free(ctx);
    free(io);



    return BPAK_OK;
}

static size_t bpak_io_file_write(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);
    size_t bytes_written = 0;

    bytes_written = fwrite(ptr, 1, size, ctx->fp);

    io->position += bytes_written;

    if (io->position > io->end_position)
        io->end_position = io->position;

    return bytes_written;
}

static size_t bpak_io_file_read(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);
    size_t bytes_read = 0;

    bytes_read = fread(ptr, 1, size, ctx->fp);

    io->position += bytes_read;

    return bytes_read;
}

static int bpak_io_file_seek(struct bpak_io *io, int64_t offset)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);

    if (fseek(ctx->fp, offset, SEEK_SET) != 0)
        return -BPAK_SEEK_ERROR;

    return BPAK_OK;
};

int bpak_io_init_file(struct bpak_io **io_, const char *filename,
                        const char *mode)
{
    int rc = BPAK_OK;

    *io_ = malloc(sizeof(struct bpak_io));

    struct bpak_io *io = *io_;

    if (!io)
        return -BPAK_FAILED;

    struct bpak_io_file_ctx *ctx = malloc(sizeof(struct bpak_io_file_ctx));

    if (!ctx)
    {
        rc = -BPAK_FAILED;
        goto err_free_io_out;
    }

    memset(ctx, 0, sizeof(struct bpak_io_file_ctx));

    ctx->filename = strdup(filename);

    rc = bpak_io_init(io, ctx);

    if (rc != BPAK_OK)
        goto err_free_ctx_out;

    ctx->fp = fopen(filename, mode);

    if (!ctx->fp)
    {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    struct stat statbuf;

    stat(filename, &statbuf);

    io->end_position = statbuf.st_size;
    io->on_write = bpak_io_file_write;
    io->on_read = bpak_io_file_read;
    io->on_seek = bpak_io_file_seek;
    io->on_close = bpak_io_file_cleanup;

    return rc;

err_free_ctx_out:
    free((void *) ctx->filename);
    free(io->priv);
err_free_io_out:
    free(io);
    return rc;
}

int bpak_io_init_random_file(struct bpak_io **io)
{
    char tmp_fn[64];
    int rc;

    snprintf(tmp_fn, sizeof(tmp_fn), "/tmp/.bpak_tmp_%x", rand());

    rc = bpak_io_init_file(io, tmp_fn, "wb+");

    if (rc != BPAK_OK)
        return rc;

    struct bpak_io_file_ctx *ctx = GET_FILE_CTX((*io));

    ctx->remove_on_close = true;

    return BPAK_OK;
}

const char *bpak_io_filename(struct bpak_io *io)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);

    return ctx->filename;
}

int bpak_io_replace_file(struct bpak_io *replacee, struct bpak_io *src)
{
    int rc;
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(replacee);

    rc = bpak_io_seek(replacee, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_io_seek(src, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    ctx->fp = freopen(NULL, "w+", ctx->fp);

    if (!ctx->fp)
        return -BPAK_FAILED;

    char buf[512];
    size_t read_bytes = 0;

    do
    {
        read_bytes = bpak_io_read(src, buf, sizeof(buf));

        if (bpak_io_write(replacee, buf, read_bytes) != read_bytes)
            return -BPAK_FAILED;

    } while(read_bytes);

    return BPAK_OK;
}


int bpak_io_file_to_fd(struct bpak_io *io)
{
    struct bpak_io_file_ctx *ctx = GET_FILE_CTX(io);
    return fileno(ctx->fp);
}
