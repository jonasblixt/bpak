#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpak/bpak.h>
#include <bpak/bsdiff.h>

#include "sais.h"

static int32_t matchlen(uint8_t *from_p,
                        int64_t from_size,
                        uint8_t *to_p,
                        int64_t to_size)
{
    int64_t i;

    for (i = 0; i < BPAK_MIN(from_size, to_size); i++)
    {
        if (from_p[i] != to_p[i])
        {
            break;
        }
    }

    return (i);
}

static int64_t search(int64_t *sa_p,
                      uint8_t *from_p,
                      int64_t from_size,
                      uint8_t *to_p,
                      int64_t to_size,
                      int64_t from_begin,
                      int64_t from_end,
                      int64_t *pos_p)
{
    int64_t x;
    int64_t y;

    if (from_end - from_begin < 2)
    {
        x = matchlen(from_p + sa_p[from_begin],
                     from_size - sa_p[from_begin],
                     to_p,
                     to_size);

        y = matchlen(from_p + sa_p[from_end],
                     from_size - sa_p[from_end],
                     to_p,
                     to_size);

        if (x > y)
        {
            *pos_p = sa_p[from_begin];

            return (x);
        }
        else
        {
            *pos_p = sa_p[from_end];

            return (y);
        }
    }

    x = (from_begin + (from_end - from_begin) / 2);

    if (memcmp(from_p + sa_p[x], to_p, BPAK_MIN(from_size - sa_p[x], to_size)) < 0)
    {
        return search(sa_p, from_p, from_size, to_p, to_size, x, from_end, pos_p);
    }
    else
    {
        return search(sa_p, from_p, from_size, to_p, to_size, from_begin, x, pos_p);
    }
}

static void offtout(int64_t x, uint8_t *buf)
{
    int64_t y;

    if(x<0) y=-x; else y=x;

    buf[0]=y%256;y-=buf[0];
    y=y/256;buf[1]=y%256;y-=buf[1];
    y=y/256;buf[2]=y%256;y-=buf[2];
    y=y/256;buf[3]=y%256;y-=buf[3];
    y=y/256;buf[4]=y%256;y-=buf[4];
    y=y/256;buf[5]=y%256;y-=buf[5];
    y=y/256;buf[6]=y%256;y-=buf[6];
    y=y/256;buf[7]=y%256;

    if(x<0) buf[7]|=0x80;
}

static int write_diff_extra_and_adjustment(struct bpak_bsdiff_context *ctx)
{
    int64_t s;
    int64_t sf;
    int64_t diff_size;
    int64_t extra_pos;
    int64_t extra_size;
    int64_t sb;
    int64_t lenb;
    int64_t overlap;
    int64_t ss;
    int64_t lens;
    int64_t i;
    int64_t last_scan;
    int64_t last_pos;
    uint64_t chunk_len = 0;
    ssize_t bytes_written = 0;
    uint8_t buffer[4096];

    last_scan = ctx->last_scan;
    last_pos = ctx->last_pos;
    s = 0;
    sf = 0;
    diff_size = 0;

    for (i = 0; (last_scan + i < ctx->scan) && (last_pos + i < ctx->origin_length);) {
        if (ctx->origin_data[last_pos + i] == ctx->new_data[last_scan + i]) {
            s++;
        }

        i++;

        if (s * 2 - i > sf * 2 - diff_size) {
            sf = s;
            diff_size = i;
        }
    }

    lenb = 0;

    if (ctx->scan < ctx->new_length) {
        s = 0;
        sb = 0;

        for (i = 1; (ctx->scan >= last_scan + i) && (ctx->pos >= i); i++) {
            if (ctx->origin_data[ctx->pos - i] == ctx->new_data[ctx->scan - i]) {
                s++;
            }

            if (s * 2 - i > sb * 2 - lenb) {
                sb = s;
                lenb = i;
            }
        }
    }

    overlap = (last_scan + diff_size) - (ctx->scan - lenb);

    if (overlap > 0) {
        s = 0;
        ss = 0;
        lens = 0;

        for (i = 0; i < overlap; i++) {
            if (ctx->new_data[last_scan + diff_size - overlap + i]
                == ctx->origin_data[last_pos + diff_size - overlap + i]) {
                s++;
            }

            if (ctx->new_data[ctx->scan - lenb + i] == ctx->origin_data[ctx->pos - lenb + i]) {
                s--;
            }

            if (s > ss) {
                ss = s;
                lens = (i + 1);
            }
        }

        diff_size += (lens - overlap);
        lenb -= lens;
    }

    extra_pos = (last_scan + diff_size);
    extra_size = (ctx->scan - lenb - extra_pos);

    /* Write control data*/
    bpak_printf(2, "diff: %10li %10li %10li\n", diff_size, extra_size,
                (ctx->pos - lenb) - (last_pos + diff_size));

    offtout(diff_size, buffer);

    bytes_written = ctx->write_output(ctx->output_pos,
                                      buffer, 8, ctx->user_priv);

    if (bytes_written < 0)
        return bytes_written;

    ctx->output_pos += bytes_written;

    offtout(extra_size, buffer);
    bytes_written = ctx->write_output(ctx->output_pos,
                                      buffer, 8, ctx->user_priv);

    if (bytes_written < 0)
        return bytes_written;

    ctx->output_pos += bytes_written;

    /* Adjustment. */
    offtout((ctx->pos - lenb) - (last_pos + diff_size), buffer);
    bytes_written = ctx->write_output(ctx->output_pos,
                                      buffer, 8, ctx->user_priv);

    if (bytes_written < 0)
        return bytes_written;

    ctx->output_pos += bytes_written;

    /* Write diff data */
    uint64_t data_to_write = diff_size;

    i = 0;

    while (data_to_write) {
        chunk_len = BPAK_MIN(data_to_write, sizeof(buffer));

        for (int n = 0; n < chunk_len; n++) {
            buffer[n] = (ctx->new_data[last_scan + i] -
                                    ctx->origin_data[last_pos + i]);
            i++;
        }

        bytes_written = ctx->write_output(ctx->output_pos,
                                          buffer, chunk_len, ctx->user_priv);

        if (bytes_written < 0)
            return bytes_written;

        if (bytes_written != chunk_len) {
            bpak_printf(0, "Error: Write error (%i != %li)\n", bytes_written,
                                                               chunk_len);
            return -BPAK_WRITE_ERROR;
        }
        ctx->output_pos += chunk_len;
        data_to_write -= chunk_len;
    }

    /* Extra data. */
    if (extra_size) {
        bytes_written = ctx->write_output(ctx->output_pos,
                                          &ctx->new_data[extra_pos], extra_size,
                                          ctx->user_priv);

        if (bytes_written < 0)
            return bytes_written;
    }

    ctx->last_scan = (ctx->scan - lenb);
    ctx->last_pos = (ctx->pos - lenb);
    ctx->last_offset = (ctx->pos - ctx->scan);

    return (0);
}

int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      void *user_priv)
{
    int rc;

    memset(ctx, 0, sizeof(*ctx));
    bpak_printf(1, "bsdiff init\n");

    ctx->write_output = write_output;
    ctx->user_priv = user_priv;
    ctx->origin_length = origin_length;
    ctx->origin_data = origin_data;
    ctx->new_length = new_length;
    ctx->new_data = new_data;

    bpak_printf(2, "Origin size: %zu bytes, new size: %zu\n", origin_length,
                                                              new_length);

    ctx->suffix_array = malloc(origin_length * sizeof(int64_t));

    if (!ctx->suffix_array) {
        return -BPAK_FAILED;
    }

    bpak_printf(2, "Initializing sais array: %p %p %zu\n",
                ctx->origin_data, ctx->suffix_array, origin_length);

    rc = sais(ctx->origin_data, ctx->suffix_array, origin_length);

    if (rc != 0) {
        bpak_printf(0, "SAIS computation failed (%i)\n", rc);
        rc = -BPAK_FAILED;
        goto err_free_suffix_array;
    }

    bpak_printf(2, "Init done\n");
    return BPAK_OK;

err_free_suffix_array:
    free(ctx->suffix_array);
    ctx->suffix_array = NULL;
    return rc;
}

int bpak_bsdiff(struct bpak_bsdiff_context *ctx)
{
    int rc;

    while (ctx->scan < ctx->new_length) {
        int64_t from_score = 0;

        ctx->scan += ctx->len;

        for (int64_t scsc = ctx->scan; ctx->scan < ctx->new_length; ctx->scan++) {

            ctx->len = search(ctx->suffix_array,
                                 ctx->origin_data,
                                 ctx->origin_length,
                                 ctx->new_data + ctx->scan,
                                 ctx->new_length - ctx->scan,
                                 0,
                                 ctx->origin_length,
                                 &(ctx->pos));

            for (; scsc < ctx->scan + ctx->len; scsc++) {
                if ((scsc + ctx->last_offset < ctx->origin_length)
                    && (ctx->origin_data[scsc + ctx->last_offset] == ctx->new_data[scsc])) {
                    from_score++;
                }
            }

            if (((ctx->len == from_score) && (ctx->len != 0)) ||
                                    (ctx->len > from_score + 8)) {
                break;
            }

            if ((ctx->scan + ctx->last_offset < ctx->origin_length)
                && (ctx->origin_data[ctx->scan + ctx->last_offset] == ctx->new_data[ctx->scan])) {
                from_score--;
            }
        }

        if ((ctx->len != from_score) || (ctx->scan == ctx->new_length)) {
            rc = write_diff_extra_and_adjustment(ctx);

            if (rc != 0) {
                return -BPAK_FAILED;
            }
        }
    }

    return BPAK_OK;
}

void bpak_bsdiff_free(struct bpak_bsdiff_context *ctx)
{
    if (ctx->suffix_array != NULL) {
        free(ctx->suffix_array);
        ctx->suffix_array = NULL;
    }
}
