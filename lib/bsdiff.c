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
#include "heatshrink/heatshrink_encoder.h"

#if BPAK_CONFIG_LZMA == 1
#include <lzma.h>
static void *lzma_alloc_wrap(void *opaque, size_t nmemb, size_t size) {
    (void) opaque;
    return bpak_calloc(nmemb, size);
}

static void lzma_free_wrap(void *opaque, void *ptr) {
    (void) opaque;
    bpak_free(ptr);
}

static const lzma_allocator lzma_alloc = {
    .alloc = lzma_alloc_wrap,
    .free = lzma_free_wrap,
};
#endif

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

#if BPAK_CONFIG_LZMA == 1
static int lzma_compressor_write(struct bpak_bsdiff_context *ctx,
                               uint8_t *buffer,
                               size_t length)
{
    lzma_stream *strm = (lzma_stream *) ctx->compressor_priv;
    lzma_action action = LZMA_RUN;

    uint8_t outbuf[BPAK_CHUNK_BUFFER_LENGTH];

    strm->next_in = buffer;
    strm->avail_in = length;
    strm->next_out = outbuf;
    strm->avail_out = sizeof(outbuf);

    while (strm->avail_in > 0) {
        lzma_ret ret = lzma_code(strm, action);
        ssize_t write_size = sizeof(outbuf) - strm->avail_out;

        if (ret != LZMA_OK) {
            bpak_printf(0, "lzma error %u\n", ret);
            return -BPAK_COMPRESSOR_ERROR;
        }

        if (write_size > 0) {
            ssize_t n_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                        outbuf, write_size, ctx->user_priv);

            if (n_written < 0)
                return n_written;
            if (n_written != write_size)
                return -BPAK_WRITE_ERROR;

            strm->next_out = outbuf;
            strm->avail_out = sizeof(outbuf);
            ctx->output_pos += n_written;
        }
    }

    return BPAK_OK;
}

static int lzma_compressor_final(struct bpak_bsdiff_context *ctx)
{
    lzma_stream *strm = (lzma_stream *) ctx->compressor_priv;
    lzma_action action = LZMA_FINISH;

    uint8_t outbuf[BPAK_CHUNK_BUFFER_LENGTH];

    strm->next_in = NULL;
    strm->avail_in = 0;
    strm->next_out = outbuf;
    strm->avail_out = sizeof(outbuf);

    while (true) {
        lzma_ret ret = lzma_code(strm, action);

        if ((ret != LZMA_OK) && (ret != LZMA_STREAM_END)) {
            bpak_printf(0, "lzma final error %u\n", ret);
            return -BPAK_COMPRESSOR_ERROR;
        }

        ssize_t write_size = sizeof(outbuf) - strm->avail_out;

        if (write_size > 0) {
            ssize_t n_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                        outbuf, write_size, ctx->user_priv);

            if (n_written < 0)
                return n_written;
            if (n_written != write_size)
                return -BPAK_WRITE_ERROR;

            strm->next_out = outbuf;
            strm->avail_out = sizeof(outbuf);
            ctx->output_pos += n_written;
        }

        if (ret == LZMA_STREAM_END)
            return BPAK_OK;

    }

    return BPAK_OK;
}

#endif  // BPAK_CONFIG_LZMA

static int hs_compressor_write(struct bpak_bsdiff_context *ctx,
                               uint8_t *buffer,
                               size_t length)
{
    heatshrink_encoder *hse = (heatshrink_encoder *) ctx->compressor_priv;

    unsigned char output_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t sunk = 0;
    ssize_t n_written;
    HSE_poll_res pres = 0;
    HSE_sink_res sres = 0;

    do {
        if (length > 0) {
            sres = heatshrink_encoder_sink(hse, &buffer[sunk],
                                            length - sunk, &sink_sz);

            if (sres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            sunk += sink_sz;
        }

        do {
            pres = heatshrink_encoder_poll(hse, output_buffer,
                                           sizeof(output_buffer),
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            if (poll_sz > 0) {
                n_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                                output_buffer, poll_sz, ctx->user_priv);
                if (n_written < 0)
                    return n_written;
                if (n_written != (ssize_t) poll_sz)
                    return -BPAK_WRITE_ERROR;
                ctx->output_pos += n_written;
            }
        } while(pres == HSER_POLL_MORE);

    } while(sunk < length);

    return BPAK_OK;
}

static int hs_compressor_final(struct bpak_bsdiff_context *ctx)
{
    heatshrink_encoder *hse = (heatshrink_encoder *) ctx->compressor_priv;
    uint8_t output_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    size_t poll_sz = 0;
    ssize_t n_written;
    HSE_poll_res pres = 0;
    HSE_finish_res fres = 0;


    do {
        fres = heatshrink_encoder_finish(hse);

        if (fres < 0)
            return -BPAK_COMPRESSOR_ERROR;

        if (fres == HSER_FINISH_MORE) {
            pres = heatshrink_encoder_poll(hse, output_buffer,
                                           sizeof(output_buffer),
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            if (poll_sz > 0) {
                n_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                                output_buffer, poll_sz, ctx->user_priv);

                if (n_written < 0)
                    return n_written;
                if (n_written != (ssize_t) poll_sz)
                    return -BPAK_WRITE_ERROR;

                ctx->output_pos += poll_sz;
            }
        }
    } while (fres == HSER_FINISH_MORE);

    return BPAK_OK;
}

static int compressor_init(struct bpak_bsdiff_context *ctx)
{
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
            ctx->compressor_priv = bpak_calloc(sizeof(heatshrink_encoder), 1);

            if (ctx->compressor_priv == NULL)
                return -BPAK_FAILED;

            heatshrink_encoder_reset((heatshrink_encoder *) ctx->compressor_priv);
        break;
#if BPAK_CONFIG_LZMA == 1
        case BPAK_COMPRESSION_LZMA:
        {
            lzma_stream *stream;
            stream = bpak_calloc(sizeof(lzma_stream), 1);
            ctx->compressor_priv = stream;

            lzma_options_lzma opt_lzma2;
            if (lzma_lzma_preset(&opt_lzma2, LZMA_PRESET_DEFAULT)) {
                bpak_free(stream);
                return -BPAK_COMPRESSOR_ERROR;
            }

            lzma_filter filters[] = {
                { .id = LZMA_FILTER_X86, .options = NULL },
                { .id = LZMA_FILTER_LZMA2, .options = &opt_lzma2 },
                { .id = LZMA_VLI_UNKNOWN, .options = NULL },
            };

            lzma_ret ret = lzma_stream_encoder(stream, filters, LZMA_CHECK_CRC64);

            if (ret != LZMA_OK)
                return -BPAK_COMPRESSOR_ERROR;

            if (stream == NULL)
                return -BPAK_FAILED;

            stream->allocator = &lzma_alloc;
        }
        break;
#endif
        default:
            return -BPAK_UNSUPPORTED_COMPRESSION;
    }

    return BPAK_OK;
}

static int compressor_write(struct bpak_bsdiff_context *ctx,
                            uint8_t *buffer,
                            size_t length)
{
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        {
            ssize_t bytes_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                              buffer, length, ctx->user_priv);

            if (bytes_written < 0)
                return bytes_written;

            if (bytes_written != (ssize_t) length) {
                bpak_printf(0, "Error: Write error (%i != %li)\n", bytes_written,
                                                                   length);
                return -BPAK_WRITE_ERROR;
            }

            ctx->output_pos += bytes_written;
        }
        break;
        case BPAK_COMPRESSION_HS:
            return hs_compressor_write(ctx, buffer, length);
        break;
#if BPAK_CONFIG_LZMA == 1
        case BPAK_COMPRESSION_LZMA:
            return lzma_compressor_write(ctx, buffer, length);
        break;
#endif
        default:
            return -BPAK_UNSUPPORTED_COMPRESSION;
    }

    return BPAK_OK;
}

static int compressor_final(struct bpak_bsdiff_context *ctx)
{
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
            return hs_compressor_final(ctx);
        break;
#if BPAK_CONFIG_LZMA == 1
        case BPAK_COMPRESSION_LZMA:
            return lzma_compressor_final(ctx);
        break;
#endif
        default:
            return -BPAK_UNSUPPORTED_COMPRESSION;
    }

    return BPAK_OK;
}

static void compressor_free(struct bpak_bsdiff_context *ctx)
{
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
            bpak_free(ctx->compressor_priv);
        break;
#if BPAK_CONFIG_LZMA == 1
        case BPAK_COMPRESSION_LZMA:
            lzma_end((lzma_stream *) ctx->compressor_priv);
            bpak_free(ctx->compressor_priv);
        break;
#endif
        default:
        break;
    }

    ctx->compressor_priv = NULL;
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
    int rc;
    uint8_t buffer[BPAK_CHUNK_BUFFER_LENGTH];

    last_scan = ctx->last_scan;
    last_pos = ctx->last_pos;
    s = 0;
    sf = 0;
    diff_size = 0;

    for (i = 0; (last_scan + i < ctx->scan) && (last_pos + i < (int64_t) ctx->origin_length);) {
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

    if (ctx->scan < (int64_t) ctx->new_length) {
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

    offtout(diff_size, &buffer[0]);
    offtout(extra_size, &buffer[8]);
    offtout((ctx->pos - lenb) - (last_pos + diff_size), &buffer[16]);

    rc = compressor_write(ctx, buffer, 24);

    if (rc != BPAK_OK)
        return rc;

    /* Write diff data */
    uint64_t data_to_write = diff_size;

    i = 0;

    while (data_to_write) {
        chunk_len = BPAK_MIN(data_to_write, sizeof(buffer));

        for (uint64_t n = 0; n < chunk_len; n++) {
            buffer[n] = (ctx->new_data[last_scan + i] -
                                    ctx->origin_data[last_pos + i]);
            i++;
        }

        rc = compressor_write(ctx, buffer, chunk_len);

        if (rc != BPAK_OK)
            return rc;
        data_to_write -= chunk_len;
    }

    /* Extra data. */
    if (extra_size) {
        rc = compressor_write(ctx, &ctx->new_data[extra_pos], extra_size);

        if (rc != BPAK_OK)
            return rc;
    }

    ctx->last_scan = (ctx->scan - lenb);
    ctx->last_pos = (ctx->pos - lenb);
    ctx->last_offset = (ctx->pos - ctx->scan);

    return BPAK_OK;
}

BPAK_EXPORT int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      off_t output_offset,
                      enum bpak_compression compression,
                      void *user_priv)
{
    int rc;

    memset(ctx, 0, sizeof(*ctx));
    bpak_printf(2, "bsdiff init: origin_length = %zu, target_length = %zu\n",
                    origin_length, new_length);

    ctx->write_output = write_output;
    ctx->output_offset = output_offset;
    ctx->user_priv = user_priv;
    ctx->origin_length = origin_length;
    ctx->origin_data = origin_data;
    ctx->new_length = new_length;
    ctx->new_data = new_data;
    ctx->compression = compression;

    rc = compressor_init(ctx);

    if (rc != BPAK_OK)
        return rc;

    ctx->suffix_array = bpak_calloc(origin_length, sizeof(int64_t));

    if (!ctx->suffix_array) {
        rc = -BPAK_FAILED;
        goto err_free_compressor_out;
    }

    bpak_printf(2, "Initializing sais array: %p %p %zu\n",
                ctx->origin_data, ctx->suffix_array, origin_length);

    rc = sais(ctx->origin_data, ctx->suffix_array, origin_length);

    if (rc != 0) {
        bpak_printf(0, "SAIS computation failed (%i)\n", rc);
        rc = -BPAK_FAILED;
        goto err_free_suffix_array_out;
    }

    bpak_printf(2, "Init done\n");
    return BPAK_OK;

err_free_suffix_array_out:
    bpak_free(ctx->suffix_array);
    ctx->suffix_array = NULL;
err_free_compressor_out:
    compressor_free(ctx);
    return rc;
}

BPAK_EXPORT ssize_t bpak_bsdiff(struct bpak_bsdiff_context *ctx)
{
    int rc;

    while (ctx->scan < (int64_t) ctx->new_length) {
        int64_t from_score = 0;

        ctx->scan += ctx->len;

        for (int64_t scsc = ctx->scan; ctx->scan < (int64_t) ctx->new_length; ctx->scan++) {

            ctx->len = search(ctx->suffix_array,
                                 ctx->origin_data,
                                 ctx->origin_length,
                                 ctx->new_data + ctx->scan,
                                 ctx->new_length - ctx->scan,
                                 0,
                                 ctx->origin_length,
                                 &(ctx->pos));

            for (; scsc < ctx->scan + ctx->len; scsc++) {
                if ((scsc + ctx->last_offset < (int64_t) ctx->origin_length)
                    && (ctx->origin_data[scsc + ctx->last_offset] == ctx->new_data[scsc])) {
                    from_score++;
                }
            }

            if (((ctx->len == from_score) && (ctx->len != 0)) ||
                                    (ctx->len > from_score + 8)) {
                break;
            }

            if ((ctx->scan + ctx->last_offset < (int64_t) ctx->origin_length)
                && (ctx->origin_data[ctx->scan + ctx->last_offset] == ctx->new_data[ctx->scan])) {
                from_score--;
            }
        }

        if ((ctx->len != from_score) || (ctx->scan == (int64_t) ctx->new_length)) {
            rc = write_diff_extra_and_adjustment(ctx);

            if (rc != 0) {
                return rc;
            }
        }
    }

    rc = compressor_final(ctx);

    if (rc != BPAK_OK)
        return rc;

    return ctx->output_pos;
}

BPAK_EXPORT void bpak_bsdiff_free(struct bpak_bsdiff_context *ctx)
{
    if (ctx->suffix_array != NULL) {
        bpak_free(ctx->suffix_array);
        ctx->suffix_array = NULL;
    }

    compressor_free(ctx);
}
