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

#if BPAK_CONFIG_THREADS == 1
#include <pthread.h>
#endif

#include "internal.h"
#include "vendor/sais/sais.h"
#include "vendor/heatshrink/heatshrink_encoder.h"

static int64_t matchlen(const uint8_t *from_p, int64_t from_size,
                        const uint8_t *to_p, int64_t to_size)
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

static int64_t search(const void *sa_p, uint8_t sa_width, const uint8_t *from_p,
                      int64_t from_size, const uint8_t *to_p, int64_t to_size,
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

#if defined(__GNUC__)
#define BSDIFF_PREFETCH(addr) __builtin_prefetch(addr)
#else
#define BSDIFF_PREFETCH(addr) ((void)(addr))
#endif

/* Maximum number of searches that run interleaved */
#define BSDIFF_SEARCH_BATCH 32

/* The prefixes of the suffixes that the first levels of the binary search
 * compare against are stored in a tree, in breadth first order. They are
 * few and stored close together, so they are mostly in the cache, unlike
 * the suffix array and origin data. Node n has the children 2n and 2n + 1.
 *
 * A prefix is the first 7 bytes of a suffix, big endian, followed by the
 * number of valid bytes. Comparing prefixes as numbers orders them like
 * memcmp() does, up to the valid length. */
#define BSDIFF_PREFIX_BYTES 7

static uint64_t prefix_get(const uint8_t *data, int64_t size)
{
    int64_t valid = BPAK_MIN(size, BSDIFF_PREFIX_BYTES);
    uint64_t prefix = 0;

    for (int64_t i = 0; i < BSDIFF_PREFIX_BYTES; i++)
        prefix = (prefix << 8) | ((i < valid) ? data[i] : 0);

    return (prefix << 8) | (uint64_t)valid;
}

/* Compare the prefixes of an origin suffix and the target. Returns a
 * negative number if the suffix is less than the target, compared like
 * search() does, a positive number if it is not and 0 if the prefixes are
 * equal and the rest of the suffix needs to be compared. */
static int prefix_compare(uint64_t suffix, uint64_t target)
{
    uint64_t valid = BPAK_MIN(suffix & 0xff, target & 0xff);
    uint64_t mask = (valid == 0) ? 0 : ~(uint64_t)0 << (64 - 8 * valid);

    if ((suffix & mask) != (target & mask))
        return ((suffix & mask) < (target & mask)) ? -1 : 1;

    /* The compared length is shorter than a prefix, everything is equal */
    if (valid < BSDIFF_PREFIX_BYTES)
        return 1;

    return 0;
}

static void search_tree_fill(struct bpak_bsdiff_context *ctx, size_t node,
                             int64_t begin, int64_t end, int level)
{
    int64_t x;
    int64_t y;

    if ((level == ctx->search_tree_levels) || (end - begin < 2))
        return;

    x = begin + (end - begin) / 2;
    y = sa_get(ctx->suffix_array, ctx->suffix_array_width, x);
    ctx->search_tree[node] =
        prefix_get(ctx->origin_data + y, ctx->origin_length - y);

    search_tree_fill(ctx, 2 * node, begin, x, level + 1);
    search_tree_fill(ctx, 2 * node + 1, x, end, level + 1);
}

static int search_tree_build(struct bpak_bsdiff_context *ctx)
{
    /* Limit the tree to about a quarter of the origin length in bytes */
    size_t max_nodes = ctx->origin_length / (4 * sizeof(uint64_t));
    int levels = 0;

    while (((size_t)2 << levels) <= max_nodes)
        levels++;

    size_t nodes = (size_t)1 << levels;

    if (ctx->search_tree_size < nodes) {
        if (ctx->search_tree != NULL)
            bpak_free(ctx->search_tree);

        ctx->search_tree = bpak_calloc(nodes, sizeof(uint64_t));

        if (ctx->search_tree == NULL) {
            ctx->search_tree_size = 0;
            return -BPAK_FAILED;
        }

        ctx->search_tree_size = nodes;
    }

    ctx->search_tree_levels = levels;
    search_tree_fill(ctx, 1, 0, ctx->origin_length, 0);

    return BPAK_OK;
}

/* Run search() for 'count' consecutive target positions, starting at
 * 'scan'. Every step of a search reads a suffix array entry and then the
 * origin data it points to, which are mostly cache misses. Stepping the
 * searches in lockstep lets the memory accesses of different searches
 * overlap. The results are the same as calling search() for each position. */
static void search_batch(const struct bpak_bsdiff_context *ctx,
                         const uint8_t *new_data, int64_t new_length,
                         int64_t scan, int count, int64_t *len_p,
                         int64_t *pos_p)
{
    const uint8_t *from_p = ctx->origin_data;
    int64_t from_size = ctx->origin_length;
    int64_t begin[BSDIFF_SEARCH_BATCH];
    int64_t end[BSDIFF_SEARCH_BATCH];
    int64_t x[BSDIFF_SEARCH_BATCH];
    int64_t y[BSDIFF_SEARCH_BATCH];
    uint64_t target[BSDIFF_SEARCH_BATCH];
    size_t node[BSDIFF_SEARCH_BATCH];
    bool active = true;

    for (int i = 0; i < count; i++) {
        begin[i] = 0;
        end[i] = from_size;
        node[i] = 1;
        target[i] = prefix_get(new_data + scan + i, new_length - (scan + i));
    }

    for (int level = 0; level < ctx->search_tree_levels; level++) {
        for (int i = 0; i < count; i++) {
            if (end[i] - begin[i] >= 2)
                BSDIFF_PREFETCH(&ctx->search_tree[node[i]]);
        }

        for (int i = 0; i < count; i++) {
            if (end[i] - begin[i] < 2)
                continue;

            int cmp = prefix_compare(ctx->search_tree[node[i]], target[i]);

            x[i] = begin[i] + (end[i] - begin[i]) / 2;

            if (cmp == 0) {
                int64_t to_size = new_length - (scan + i);

                y[i] = sa_get(ctx->suffix_array, ctx->suffix_array_width, x[i]);
                cmp = memcmp(from_p + y[i],
                             new_data + scan + i,
                             BPAK_MIN(from_size - y[i], to_size));
            }

            if (cmp < 0) {
                begin[i] = x[i];
                node[i] = 2 * node[i] + 1;
            } else {
                end[i] = x[i];
                node[i] = 2 * node[i];
            }
        }
    }

    while (active) {
        active = false;

        for (int i = 0; i < count; i++) {
            if (end[i] - begin[i] >= 2) {
                x[i] = begin[i] + (end[i] - begin[i]) / 2;
                BSDIFF_PREFETCH((const uint8_t *)ctx->suffix_array +
                                x[i] * ctx->suffix_array_width);
                active = true;
            }
        }

        for (int i = 0; i < count; i++) {
            if (end[i] - begin[i] >= 2) {
                y[i] = sa_get(ctx->suffix_array, ctx->suffix_array_width, x[i]);
                BSDIFF_PREFETCH(from_p + y[i]);
            }
        }

        for (int i = 0; i < count; i++) {
            if (end[i] - begin[i] >= 2) {
                int64_t to_size = new_length - (scan + i);

                if (memcmp(from_p + y[i],
                           new_data + scan + i,
                           BPAK_MIN(from_size - y[i], to_size)) < 0) {
                    begin[i] = x[i];
                } else {
                    end[i] = x[i];
                }
            }
        }
    }

    for (int i = 0; i < count; i++) {
        len_p[i] = search(ctx->suffix_array,
                          ctx->suffix_array_width,
                          ctx->origin_data,
                          ctx->origin_length,
                          new_data + scan + i,
                          new_length - (scan + i),
                          begin[i],
                          end[i],
                          &pos_p[i]);
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

/* Diff state for a part of the target chunk. A chunk is split into segments
 * that are diffed independently, possibly in parallel, and are output in
 * order. The last record of a segment moves the origin position to where the
 * next segment starts. */
struct bsdiff_segment {
    struct bpak_bsdiff_context *ctx;
    uint8_t *new_data;  /* Target data of the segment */
    int64_t new_start;  /* Offset of the segment in the chunk */
    int64_t new_length; /* Length of the segment */
    int64_t end_pos;    /* Origin position, in window coordinates, that the
                           next segment starts at, or -1 for the last one */
    bool direct;        /* Write to the compressor instead of the buffer */
    int64_t scan;
    int64_t len;
    int64_t pos;
    int64_t last_scan;
    int64_t last_pos;
    int64_t last_offset;
    uint8_t *buffer; /* Output of a segment that is not written directly */
    size_t buffer_length;
    size_t buffer_capacity;
    bool done;
    int rc;
};

static int segment_write(struct bsdiff_segment *seg, uint8_t *data,
                         size_t length)
{
    if (seg->direct)
        return compressor_write(seg->ctx, data, length);

    if (seg->buffer_length + length > seg->buffer_capacity) {
        /* The output is about as large as the target data */
        size_t capacity = seg->buffer_capacity * 2;
        size_t initial = seg->new_length + seg->new_length / 16 + 1024;
        uint8_t *buffer;

        if (capacity < initial)
            capacity = initial;
        if (capacity < seg->buffer_length + length)
            capacity = seg->buffer_length + length;

        buffer = bpak_calloc(capacity, 1);

        if (buffer == NULL)
            return -BPAK_FAILED;

        if (seg->buffer != NULL) {
            memcpy(buffer, seg->buffer, seg->buffer_length);
            bpak_free(seg->buffer);
        }

        seg->buffer = buffer;
        seg->buffer_capacity = capacity;
    }

    memcpy(seg->buffer + seg->buffer_length, data, length);
    seg->buffer_length += length;

    return BPAK_OK;
}

static int write_diff_extra_and_adjustment(struct bsdiff_segment *seg)
{
    struct bpak_bsdiff_context *ctx = seg->ctx;
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

    last_scan = seg->last_scan;
    last_pos = seg->last_pos;
    s = 0;
    sf = 0;
    diff_size = 0;

    for (i = 0; (last_scan + i < seg->scan) &&
                (last_pos + i < (int64_t)ctx->origin_length);) {
        if (ctx->origin_data[last_pos + i] == seg->new_data[last_scan + i]) {
            s++;
        }

        i++;

        if (s * 2 - i > sf * 2 - diff_size) {
            sf = s;
            diff_size = i;
        }
    }

    lenb = 0;

    if (seg->scan < (int64_t)seg->new_length) {
        s = 0;
        sb = 0;

        for (i = 1; (seg->scan >= last_scan + i) && (seg->pos >= i); i++) {
            if (ctx->origin_data[seg->pos - i] ==
                seg->new_data[seg->scan - i]) {
                s++;
            }

            if (s * 2 - i > sb * 2 - lenb) {
                sb = s;
                lenb = i;
            }
        }
    }

    overlap = (last_scan + diff_size) - (seg->scan - lenb);

    if (overlap > 0) {
        s = 0;
        ss = 0;
        lens = 0;

        for (i = 0; i < overlap; i++) {
            if (seg->new_data[last_scan + diff_size - overlap + i] ==
                ctx->origin_data[last_pos + diff_size - overlap + i]) {
                s++;
            }

            if (seg->new_data[seg->scan - lenb + i] ==
                ctx->origin_data[seg->pos - lenb + i]) {
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
    extra_size = (seg->scan - lenb - extra_pos);

    adjust_to = seg->pos - lenb;
    chunk_end = false;

    if ((seg->scan == seg->new_length) && (seg->end_pos >= 0)) {
        /* bspatch moves the origin position by a relative adjustment after
         * every record. Let the last record of this segment move it to
         * where the next segment starts. */
        adjust_to = seg->end_pos;
    } else if ((seg->scan == seg->new_length) && more_chunks(ctx)) {
        /* The next chunk continues with the offset of the latest match,
         * in its window's coordinates. It is clamped to the window since
         * only the end of the window is checked when it is used. */
        chunk_end = true;
        next_new_base = ctx->new_base + ctx->new_length;
        drift = seg->last_offset + ctx->origin_base -
                (ctx->new_base + seg->new_start);
        window_select(ctx, next_new_base, drift);
        next_offset = drift + next_new_base - ctx->next_origin_base;

        if (next_offset < 0)
            next_offset = 0;
        if (next_offset > (int64_t)ctx->next_origin_length)
            next_offset = ctx->next_origin_length;

        /* Let the last record of this chunk move the origin position to
         * where the next chunk starts. */
        adjust_to = ctx->next_origin_base + next_offset - ctx->origin_base;
    }

    /* Write control data */
    offtout(diff_size, &buffer[0]);
    offtout(extra_size, &buffer[8]);
    offtout(adjust_to - (last_pos + diff_size), &buffer[16]);

    rc = segment_write(seg, buffer, 24);

    if (rc != BPAK_OK)
        return rc;

    /* Write diff data */
    uint64_t data_to_write = diff_size;

    i = 0;

    while (data_to_write) {
        chunk_len = BPAK_MIN(data_to_write, sizeof(buffer));

        for (uint64_t n = 0; n < chunk_len; n++) {
            buffer[n] =
                (seg->new_data[last_scan + i] - ctx->origin_data[last_pos + i]);
            i++;
        }

        rc = segment_write(seg, buffer, chunk_len);

        if (rc != BPAK_OK)
            return rc;
        data_to_write -= chunk_len;
    }

    /* Extra data. */
    if (extra_size) {
        rc = segment_write(seg, &seg->new_data[extra_pos], extra_size);

        if (rc != BPAK_OK)
            return rc;
    }

    seg->last_scan = (seg->scan - lenb);
    seg->last_pos = (seg->pos - lenb);
    seg->last_offset = (seg->pos - seg->scan);

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

    rc = search_tree_build(ctx);

    if (rc != BPAK_OK)
        return rc;

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

static int segment_run(struct bsdiff_segment *seg)
{
    const struct bpak_bsdiff_context *ctx = seg->ctx;
    int rc;

    /* Results of search_batch() for target positions batch_start to
     * batch_start + batch_count */
    int64_t batch_len[BSDIFF_SEARCH_BATCH];
    int64_t batch_pos[BSDIFF_SEARCH_BATCH];
    int64_t batch_start = 0;
    int64_t batch_count = 0;
    int batch_size = 1;

    while (seg->scan < seg->new_length) {
        int64_t from_score = 0;

        seg->scan += seg->len;

        for (int64_t scsc = seg->scan; seg->scan < seg->new_length;
             seg->scan++) {

            if ((seg->scan < batch_start) ||
                (seg->scan >= batch_start + batch_count)) {
                /* Searches are mostly for consecutive positions. Grow the
                 * batch while they are, so that few results are thrown away
                 * when the scan jumps ahead. */
                if (seg->scan == batch_start + batch_count)
                    batch_size = BPAK_MIN(batch_size * 2, BSDIFF_SEARCH_BATCH);
                else
                    batch_size = 1;

                batch_start = seg->scan;
                batch_count =
                    BPAK_MIN((int64_t)batch_size, seg->new_length - seg->scan);
                search_batch(ctx,
                             seg->new_data,
                             seg->new_length,
                             batch_start,
                             batch_count,
                             batch_len,
                             batch_pos);
            }

            seg->len = batch_len[seg->scan - batch_start];
            seg->pos = batch_pos[seg->scan - batch_start];

            for (; scsc < seg->scan + seg->len; scsc++) {
                if ((scsc + seg->last_offset < (int64_t)ctx->origin_length) &&
                    (ctx->origin_data[scsc + seg->last_offset] ==
                     seg->new_data[scsc])) {
                    from_score++;
                }
            }

            if (((seg->len == from_score) && (seg->len != 0)) ||
                (seg->len > from_score + 8)) {
                break;
            }

            if ((seg->scan + seg->last_offset < (int64_t)ctx->origin_length) &&
                (ctx->origin_data[seg->scan + seg->last_offset] ==
                 seg->new_data[seg->scan])) {
                from_score--;
            }
        }

        if ((seg->len != from_score) || (seg->scan == seg->new_length)) {
            rc = write_diff_extra_and_adjustment(seg);

            if (rc != 0) {
                return rc;
            }
        }
    }

    return BPAK_OK;
}

#if BPAK_CONFIG_THREADS == 1
/* Segments are diffed by worker threads, while the calling thread writes
 * the finished segments, in order, to the compressor. */
struct bsdiff_workers {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct bsdiff_segment *segments;
    size_t count;
    size_t next;      /* Next segment to diff */
    size_t output;    /* Next segment to write to the compressor */
    size_t max_ahead; /* Limits the memory used for segment output */
    bool abort;
};

static void *segment_worker(void *arg)
{
    struct bsdiff_workers *w = (struct bsdiff_workers *)arg;

    pthread_mutex_lock(&w->lock);

    while (true) {
        while (!w->abort && (w->next < w->count) &&
               (w->next >= w->output + w->max_ahead)) {
            pthread_cond_wait(&w->cond, &w->lock);
        }

        if (w->abort || (w->next >= w->count))
            break;

        struct bsdiff_segment *seg = &w->segments[w->next++];

        pthread_mutex_unlock(&w->lock);
        int rc = segment_run(seg);
        pthread_mutex_lock(&w->lock);

        seg->rc = rc;
        seg->done = true;
        pthread_cond_broadcast(&w->cond);
    }

    pthread_mutex_unlock(&w->lock);
    return NULL;
}

static int segments_run_parallel(struct bpak_bsdiff_context *ctx,
                                 struct bsdiff_segment *segments, size_t count)
{
    struct bsdiff_workers w;
    pthread_t threads[BPAK_BSDIFF_MAX_THREADS];
    size_t n_threads = BPAK_MIN((size_t)ctx->threads, count);
    size_t started = 0;
    int rc = BPAK_OK;

    memset(&w, 0, sizeof(w));
    w.segments = segments;
    w.count = count;
    w.max_ahead = 2 * n_threads;

    if (pthread_mutex_init(&w.lock, NULL) != 0)
        return -BPAK_FAILED;

    if (pthread_cond_init(&w.cond, NULL) != 0) {
        pthread_mutex_destroy(&w.lock);
        return -BPAK_FAILED;
    }

    for (started = 0; started < n_threads; started++) {
        if (pthread_create(&threads[started], NULL, segment_worker, &w) != 0)
            break;
    }

    if (started == 0) {
        rc = -BPAK_FAILED;
        goto err_destroy;
    }

    for (size_t i = 0; i < count; i++) {
        struct bsdiff_segment *seg = &segments[i];

        pthread_mutex_lock(&w.lock);
        while (!seg->done)
            pthread_cond_wait(&w.cond, &w.lock);
        pthread_mutex_unlock(&w.lock);

        rc = seg->rc;

        if (rc == BPAK_OK)
            rc = compressor_write(ctx, seg->buffer, seg->buffer_length);

        if (seg->buffer != NULL) {
            bpak_free(seg->buffer);
            seg->buffer = NULL;
        }

        pthread_mutex_lock(&w.lock);
        w.output = i + 1;
        w.abort = (rc != BPAK_OK);
        pthread_cond_broadcast(&w.cond);
        pthread_mutex_unlock(&w.lock);

        if (rc != BPAK_OK)
            break;
    }

    for (size_t i = 0; i < started; i++)
        pthread_join(threads[i], NULL);

err_destroy:
    pthread_cond_destroy(&w.cond);
    pthread_mutex_destroy(&w.lock);
    return rc;
}
#endif

/* Diff the current chunk against the current origin window */
static int chunk_diff(struct bpak_bsdiff_context *ctx)
{
    size_t segment_size = ctx->new_length;
    size_t count = 1;
    struct bsdiff_segment *segments;
    int rc = BPAK_OK;

    if ((ctx->segment_size > 0) && (ctx->segment_size < ctx->new_length)) {
        segment_size = ctx->segment_size;
        count = (ctx->new_length + segment_size - 1) / segment_size;
    }

    segments = bpak_calloc(count, sizeof(*segments));

    if (segments == NULL)
        return -BPAK_FAILED;

    /* The chunk starts at the offset of the previous chunk's latest match.
     * The following segments assume that the offset is the same, since the
     * previous segment is not necessarily diffed yet. */
    for (size_t i = 0; i < count; i++) {
        struct bsdiff_segment *seg = &segments[i];
        int64_t start_pos = i * segment_size + ctx->last_offset;

        if (start_pos > (int64_t)ctx->origin_length)
            start_pos = ctx->origin_length;

        seg->ctx = ctx;
        seg->new_start = i * segment_size;
        seg->new_length =
            BPAK_MIN(segment_size, ctx->new_length - seg->new_start);
        seg->new_data = ctx->new_data + seg->new_start;
        seg->last_pos = start_pos;
        seg->last_offset = start_pos;
        seg->end_pos = -1;

        if (i > 0)
            segments[i - 1].end_pos = start_pos;
    }

#if BPAK_CONFIG_THREADS == 1
    if ((ctx->threads > 1) && (count > 1)) {
        rc = segments_run_parallel(ctx, segments, count);
        goto out_free;
    }
#endif

    for (size_t i = 0; i < count; i++) {
        segments[i].direct = true;
        rc = segment_run(&segments[i]);

        if (rc != BPAK_OK)
            break;
    }

#if BPAK_CONFIG_THREADS == 1
out_free:
#endif
    for (size_t i = 0; i < count; i++) {
        if (segments[i].buffer != NULL)
            bpak_free(segments[i].buffer);
    }

    bpak_free(segments);
    return rc;
}

BPAK_EXPORT int bpak_bsdiff_set_threads(struct bpak_bsdiff_context *ctx,
                                        unsigned int threads,
                                        size_t segment_size)
{
    if (ctx->suffix_array != NULL)
        return -BPAK_FAILED;

#if BPAK_CONFIG_THREADS == 1
    if (threads > BPAK_BSDIFF_MAX_THREADS)
        threads = BPAK_BSDIFF_MAX_THREADS;
#else
    threads = 1;
#endif

    ctx->threads = (threads == 0) ? 1 : threads;
    ctx->segment_size = segment_size;

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

        rc = chunk_diff(ctx);

        if (rc != BPAK_OK)
            return rc;

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

    if (ctx->search_tree != NULL) {
        bpak_free(ctx->search_tree);
        ctx->search_tree = NULL;
    }

    compressor_free(ctx);
}
