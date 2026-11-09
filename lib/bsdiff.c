/*-
 * Copyright 2003-2005 Colin Percival
 * Copyright 2012 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/bsdiff.h>

#include "internal.h"
#include "vendor/sais/sais.h"
#include "vendor/heatshrink/heatshrink_encoder.h"

static int64_t matchlen(uint8_t *from_p, int64_t from_size, uint8_t *to_p,
                        int64_t to_size)
{
    int64_t i;

    for (i = 0; i < BPAK_MIN(from_size, to_size); i++) {
        if (from_p[i] != to_p[i]) {
            break;
        }
    }

    return (i);
}

static inline int64_t sa_get(const void *sa_p, uint8_t sa_width, int64_t i)
{
    if (sa_width == sizeof(int32_t))
        return ((const int32_t *)sa_p)[i];

    return ((const int64_t *)sa_p)[i];
}

static int64_t search(const void *sa_p, uint8_t sa_width, uint8_t *from_p,
                      int64_t from_size, uint8_t *to_p, int64_t to_size,
                      int64_t from_begin, int64_t from_end, int64_t *pos_p)
{
    int64_t x;
    int64_t y;
    int64_t sa_begin;
    int64_t sa_end;

    if (from_end - from_begin < 2) {
        sa_begin = sa_get(sa_p, sa_width, from_begin);
        sa_end = sa_get(sa_p, sa_width, from_end);

        x = matchlen(from_p + sa_begin, from_size - sa_begin, to_p, to_size);
        y = matchlen(from_p + sa_end, from_size - sa_end, to_p, to_size);

        if (x > y) {
            *pos_p = sa_begin;

            return (x);
        } else {
            *pos_p = sa_end;

            return (y);
        }
    }

    x = (from_begin + (from_end - from_begin) / 2);
    y = sa_get(sa_p, sa_width, x);

    if (memcmp(from_p + y, to_p, BPAK_MIN(from_size - y, to_size)) < 0) {
        return search(sa_p,
                      sa_width,
                      from_p,
                      from_size,
                      to_p,
                      to_size,
                      x,
                      from_end,
                      pos_p);
    } else {
        return search(sa_p,
                      sa_width,
                      from_p,
                      from_size,
                      to_p,
                      to_size,
                      from_begin,
                      x,
                      pos_p);
    }
}

/* Sign and magnitude, little endian */
static void offtout(int64_t x, uint8_t *buf)
{
    uint64_t y = (x < 0) ? -(uint64_t)x : (uint64_t)x;

    for (int i = 0; i < 8; i++) {
        buf[i] = y & 0xff;
        y >>= 8;
    }

    if (x < 0)
        buf[7] |= 0x80;
}

/* Write output after the output that was written before */
static int output_write(struct bpak_bsdiff_context *ctx, uint8_t *buffer,
                        size_t length)
{
    if (length == 0)
        return BPAK_OK;

    ssize_t n_written = ctx->write_output(ctx->output_offset + ctx->output_pos,
                                          buffer,
                                          length,
                                          ctx->user_priv);

    if (n_written < 0)
        return n_written;

    if (n_written != (ssize_t)length) {
        bpak_printf(0, "Error: Write error (%zd != %zu)\n", n_written, length);
        return -BPAK_WRITE_ERROR;
    }

    ctx->output_pos += n_written;
    return BPAK_OK;
}

#if BPAK_CONFIG_LZMA == 1
/* Compress 'length' bytes with LZMA_RUN, or finish the stream with
 * LZMA_FINISH */
static int lzma_compressor_code(struct bpak_bsdiff_context *ctx,
                                uint8_t *buffer, size_t length,
                                lzma_action action)
{
    lzma_stream *strm = (lzma_stream *)ctx->compressor_priv;
    uint8_t outbuf[BPAK_CHUNK_BUFFER_LENGTH];
    int rc;

    strm->next_in = buffer;
    strm->avail_in = length;

    while (action == LZMA_FINISH || strm->avail_in > 0) {
        strm->next_out = outbuf;
        strm->avail_out = sizeof(outbuf);

        lzma_ret ret = lzma_code(strm, action);

        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
            bpak_printf(0, "lzma error %u\n", ret);
            return -BPAK_COMPRESSOR_ERROR;
        }

        rc = output_write(ctx, outbuf, sizeof(outbuf) - strm->avail_out);

        if (rc != BPAK_OK)
            return rc;

        if (ret == LZMA_STREAM_END)
            break;
    }

    return BPAK_OK;
}
#endif // BPAK_CONFIG_LZMA

/* Write the output of the heatshrink encoder until it needs more input */
static int hs_compressor_poll(struct bpak_bsdiff_context *ctx)
{
    heatshrink_encoder *hse = (heatshrink_encoder *)ctx->compressor_priv;
    uint8_t output_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    size_t poll_sz = 0;
    HSE_poll_res pres;
    int rc;

    do {
        pres = heatshrink_encoder_poll(hse,
                                       output_buffer,
                                       sizeof(output_buffer),
                                       &poll_sz);

        if (pres < 0)
            return -BPAK_COMPRESSOR_ERROR;

        rc = output_write(ctx, output_buffer, poll_sz);

        if (rc != BPAK_OK)
            return rc;
    } while (pres == HSER_POLL_MORE);

    return BPAK_OK;
}

static int hs_compressor_write(struct bpak_bsdiff_context *ctx, uint8_t *buffer,
                               size_t length)
{
    heatshrink_encoder *hse = (heatshrink_encoder *)ctx->compressor_priv;
    size_t sink_sz = 0;
    size_t sunk = 0;
    int rc;

    do {
        if (length > 0) {
            HSE_sink_res sres = heatshrink_encoder_sink(hse,
                                                        &buffer[sunk],
                                                        length - sunk,
                                                        &sink_sz);

            if (sres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            sunk += sink_sz;
        }

        rc = hs_compressor_poll(ctx);

        if (rc != BPAK_OK)
            return rc;
    } while (sunk < length);

    return BPAK_OK;
}

static int hs_compressor_final(struct bpak_bsdiff_context *ctx)
{
    heatshrink_encoder *hse = (heatshrink_encoder *)ctx->compressor_priv;
    HSE_finish_res fres;
    int rc;

    while ((fres = heatshrink_encoder_finish(hse)) == HSER_FINISH_MORE) {
        rc = hs_compressor_poll(ctx);

        if (rc != BPAK_OK)
            return rc;
    }

    return (fres < 0) ? -BPAK_COMPRESSOR_ERROR : BPAK_OK;
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

        heatshrink_encoder_reset((heatshrink_encoder *)ctx->compressor_priv);
        break;
#if BPAK_CONFIG_LZMA == 1
    case BPAK_COMPRESSION_LZMA: {
        lzma_stream *stream;
        stream = bpak_calloc(sizeof(lzma_stream), 1);

        if (stream == NULL)
            return -BPAK_FAILED;

        lzma_options_lzma opt_lzma2;
        if (lzma_lzma_preset(&opt_lzma2, LZMA_PRESET_DEFAULT)) {
            bpak_free(stream);
            return -BPAK_COMPRESSOR_ERROR;
        }

        lzma_filter filters[] = {
            {.id = LZMA_FILTER_X86, .options = NULL},
            {.id = LZMA_FILTER_LZMA2, .options = &opt_lzma2},
            {.id = LZMA_VLI_UNKNOWN, .options = NULL},
        };

        /* liblzma allocates the encoder with the allocator of the stream */
        stream->allocator = &bpak_lzma_allocator;

        lzma_ret ret = lzma_stream_encoder(stream, filters, LZMA_CHECK_CRC64);

        if (ret != LZMA_OK) {
            bpak_free(stream);
            return -BPAK_COMPRESSOR_ERROR;
        }

        ctx->compressor_priv = stream;
    } break;
#endif
    default:
        return -BPAK_UNSUPPORTED_COMPRESSION;
    }

    return BPAK_OK;
}

static int compressor_write(struct bpak_bsdiff_context *ctx, uint8_t *buffer,
                            size_t length)
{
    switch (ctx->compression) {
    case BPAK_COMPRESSION_NONE:
        return output_write(ctx, buffer, length);
    case BPAK_COMPRESSION_HS:
        return hs_compressor_write(ctx, buffer, length);
#if BPAK_CONFIG_LZMA == 1
    case BPAK_COMPRESSION_LZMA:
        return lzma_compressor_code(ctx, buffer, length, LZMA_RUN);
#endif
    default:
        return -BPAK_UNSUPPORTED_COMPRESSION;
    }
}

static int compressor_final(struct bpak_bsdiff_context *ctx)
{
    switch (ctx->compression) {
    case BPAK_COMPRESSION_NONE:
        return BPAK_OK;
    case BPAK_COMPRESSION_HS:
        return hs_compressor_final(ctx);
#if BPAK_CONFIG_LZMA == 1
    case BPAK_COMPRESSION_LZMA:
        return lzma_compressor_code(ctx, NULL, 0, LZMA_FINISH);
#endif
    default:
        return -BPAK_UNSUPPORTED_COMPRESSION;
    }
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
        lzma_end((lzma_stream *)ctx->compressor_priv);
        bpak_free(ctx->compressor_priv);
        break;
#endif
    default:
        break;
    }

    ctx->compressor_priv = NULL;
}

static size_t chunk_length(const struct bpak_bsdiff_context *ctx,
                           int64_t new_base)
{
    size_t remaining = ctx->new_full_length - new_base;

    if ((ctx->chunk_size == 0) || (remaining <= ctx->chunk_size))
        return remaining;

    /* Avoid a short last chunk by merging it with the one before */
    if (remaining - ctx->chunk_size < ctx->chunk_size / 2)
        return remaining;

    return ctx->chunk_size;
}

static bool more_chunks(const struct bpak_bsdiff_context *ctx)
{
    return (ctx->new_base + ctx->new_length) < ctx->new_full_length;
}

/* Select the origin window for the chunk starting at new_base. drift is
 * the offset of origin data relative to target data at the latest match. */
static void window_select(struct bpak_bsdiff_context *ctx, int64_t new_base,
                          int64_t drift)
{
    size_t margin = BPAK_MIN(ctx->window_margin, ctx->origin_full_length);
    size_t length;
    int64_t base;

    if (ctx->chunk_size == 0) {
        ctx->next_origin_base = 0;
        ctx->next_origin_length = ctx->origin_full_length;
        return;
    }

    length = BPAK_MIN(chunk_length(ctx, new_base), ctx->origin_full_length);
    length = BPAK_MIN(length + 2 * margin, ctx->origin_full_length);
    base = new_base + drift - (int64_t)margin;

    if (base > (int64_t)(ctx->origin_full_length - length))
        base = ctx->origin_full_length - length;
    if (base < 0)
        base = 0;

    ctx->next_origin_base = base;
    ctx->next_origin_length = length;
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
    int64_t adjust_to;
    int64_t drift = 0;
    int64_t next_new_base = 0;
    int64_t next_offset = 0;
    bool chunk_end;
    uint64_t chunk_len = 0;
    int rc;
    uint8_t buffer[BPAK_CHUNK_BUFFER_LENGTH];

    last_scan = ctx->last_scan;
    last_pos = ctx->last_pos;
    s = 0;
    sf = 0;
    diff_size = 0;

    for (i = 0; (last_scan + i < ctx->scan) &&
                (last_pos + i < (int64_t)ctx->origin_length);) {
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

    if (ctx->scan < (int64_t)ctx->new_length) {
        s = 0;
        sb = 0;

        for (i = 1; (ctx->scan >= last_scan + i) && (ctx->pos >= i); i++) {
            if (ctx->origin_data[ctx->pos - i] ==
                ctx->new_data[ctx->scan - i]) {
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
            if (ctx->new_data[last_scan + diff_size - overlap + i] ==
                ctx->origin_data[last_pos + diff_size - overlap + i]) {
                s++;
            }

            if (ctx->new_data[ctx->scan - lenb + i] ==
                ctx->origin_data[ctx->pos - lenb + i]) {
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

    adjust_to = ctx->pos - lenb;
    chunk_end = (ctx->scan == (int64_t)ctx->new_length) && more_chunks(ctx);

    if (chunk_end) {
        /* The next chunk continues with the offset of the latest match,
         * in its window's coordinates. It is clamped to the window since
         * only the end of the window is checked when it is used. */
        next_new_base = ctx->new_base + ctx->new_length;
        drift = ctx->last_offset + ctx->origin_base - ctx->new_base;
        window_select(ctx, next_new_base, drift);
        next_offset = drift + next_new_base - ctx->next_origin_base;

        if (next_offset < 0)
            next_offset = 0;
        if (next_offset > (int64_t)ctx->next_origin_length)
            next_offset = ctx->next_origin_length;

        /* bspatch moves the origin position by a relative adjustment after
         * every record. Let the last record of this chunk move it to where
         * the next chunk starts. */
        adjust_to = ctx->next_origin_base + next_offset - ctx->origin_base;
    }

    /* Write control data*/
    offtout(diff_size, &buffer[0]);
    offtout(extra_size, &buffer[8]);
    offtout(adjust_to - (last_pos + diff_size), &buffer[16]);

    rc = compressor_write(ctx, buffer, 24);

    if (rc != BPAK_OK)
        return rc;

    /* Write diff data */
    uint64_t data_to_write = diff_size;

    i = 0;

    while (data_to_write) {
        chunk_len = BPAK_MIN(data_to_write, sizeof(buffer));

        for (uint64_t n = 0; n < chunk_len; n++) {
            buffer[n] =
                (ctx->new_data[last_scan + i] - ctx->origin_data[last_pos + i]);
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

    if (chunk_end)
        ctx->last_offset = next_offset;

    return BPAK_OK;
}

static int suffix_array_build(struct bpak_bsdiff_context *ctx)
{
    /* search() may read one entry past the last suffix, the extra entry
     * is zeroed so that it refers to the first suffix. */
    size_t entries = ctx->origin_length + 1;
    uint8_t width =
        (ctx->origin_length < INT32_MAX) ? sizeof(int32_t) : sizeof(int64_t);
    int rc;

    if ((ctx->suffix_array != NULL) &&
        (ctx->sa_origin_base == ctx->origin_base) &&
        (ctx->sa_origin_length == ctx->origin_length))
        return BPAK_OK;

    if ((ctx->suffix_array == NULL) || (ctx->suffix_array_width != width) ||
        (ctx->suffix_array_size < entries)) {
        if (ctx->suffix_array != NULL)
            bpak_free(ctx->suffix_array);

        ctx->suffix_array = bpak_calloc(entries, width);

        if (ctx->suffix_array == NULL) {
            ctx->suffix_array_size = 0;
            return -BPAK_FAILED;
        }

        ctx->suffix_array_size = entries;
        ctx->suffix_array_width = width;
    }

    if (width == sizeof(int32_t)) {
        ((int32_t *)ctx->suffix_array)[ctx->origin_length] = 0;
        rc = sais32(ctx->origin_data,
                    (int32_t *)ctx->suffix_array,
                    (int32_t)ctx->origin_length);
    } else {
        ((int64_t *)ctx->suffix_array)[ctx->origin_length] = 0;
        rc = sais64(ctx->origin_data,
                    (int64_t *)ctx->suffix_array,
                    (int64_t)ctx->origin_length);
    }

    if (rc != 0) {
        bpak_printf(0, "SAIS computation failed (%i)\n", rc);
        return -BPAK_FAILED;
    }

    ctx->sa_origin_base = ctx->origin_base;
    ctx->sa_origin_length = ctx->origin_length;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx,
                                 uint8_t *origin_data, size_t origin_length,
                                 uint8_t *new_data, size_t new_length,
                                 bpak_io_t write_output, off_t output_offset,
                                 enum bpak_compression compression,
                                 void *user_priv)
{
    int rc;

    memset(ctx, 0, sizeof(*ctx));
    bpak_printf(2,
                "bsdiff init: origin_length = %zu, target_length = %zu\n",
                origin_length,
                new_length);

    ctx->write_output = write_output;
    ctx->output_offset = output_offset;
    ctx->user_priv = user_priv;
    ctx->origin_full_length = origin_length;
    ctx->origin_full = origin_data;
    ctx->new_full_length = new_length;
    ctx->new_full = new_data;
    ctx->compression = compression;

    rc = compressor_init(ctx);

    if (rc != BPAK_OK)
        return rc;

    /* The suffix array is built by bpak_bsdiff, once the origin window is
     * known */
    return BPAK_OK;
}

BPAK_EXPORT int bpak_bsdiff_set_chunking(struct bpak_bsdiff_context *ctx,
                                         size_t chunk_size,
                                         size_t window_margin)
{
    if (ctx->suffix_array != NULL)
        return -BPAK_FAILED;

    ctx->chunk_size = chunk_size;
    ctx->window_margin = window_margin;

    return BPAK_OK;
}

BPAK_EXPORT ssize_t bpak_bsdiff(struct bpak_bsdiff_context *ctx)
{
    int rc;

    window_select(ctx, 0, 0);

    do {
        ctx->new_data = ctx->new_full + ctx->new_base;
        ctx->new_length = chunk_length(ctx, ctx->new_base);
        ctx->origin_base = ctx->next_origin_base;
        ctx->origin_length = ctx->next_origin_length;
        ctx->origin_data = ctx->origin_full + ctx->origin_base;

        bpak_printf(2,
                    "bsdiff chunk: target %" PRIi64 "+%zu, origin %" PRIi64 "+%zu\n",
                    ctx->new_base,
                    ctx->new_length,
                    ctx->origin_base,
                    ctx->origin_length);

        rc = suffix_array_build(ctx);

        if (rc != BPAK_OK)
            return rc;

        /* The scan starts over in every chunk, aligned with the offset of
         * the previous chunk's latest match */
        ctx->scan = 0;
        ctx->len = 0;
        ctx->pos = 0;
        ctx->last_scan = 0;
        ctx->last_pos = ctx->last_offset;

        while (ctx->scan < (int64_t)ctx->new_length) {
            int64_t from_score = 0;

            ctx->scan += ctx->len;

            for (int64_t scsc = ctx->scan; ctx->scan < (int64_t)ctx->new_length;
                 ctx->scan++) {

                ctx->len = search(ctx->suffix_array,
                                  ctx->suffix_array_width,
                                  ctx->origin_data,
                                  ctx->origin_length,
                                  ctx->new_data + ctx->scan,
                                  ctx->new_length - ctx->scan,
                                  0,
                                  ctx->origin_length,
                                  &(ctx->pos));

                for (; scsc < ctx->scan + ctx->len; scsc++) {
                    if ((scsc + ctx->last_offset <
                         (int64_t)ctx->origin_length) &&
                        (ctx->origin_data[scsc + ctx->last_offset] ==
                         ctx->new_data[scsc])) {
                        from_score++;
                    }
                }

                if (((ctx->len == from_score) && (ctx->len != 0)) ||
                    (ctx->len > from_score + 8)) {
                    break;
                }

                if ((ctx->scan + ctx->last_offset <
                     (int64_t)ctx->origin_length) &&
                    (ctx->origin_data[ctx->scan + ctx->last_offset] ==
                     ctx->new_data[ctx->scan])) {
                    from_score--;
                }
            }

            if ((ctx->len != from_score) ||
                (ctx->scan == (int64_t)ctx->new_length)) {
                rc = write_diff_extra_and_adjustment(ctx);

                if (rc != 0) {
                    return rc;
                }
            }
        }

        ctx->new_base += ctx->new_length;
    } while (ctx->new_base < (int64_t)ctx->new_full_length);

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
