#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/bspatch.h>

#include "heatshrink/heatshrink_decoder.h"

#ifdef BPAK_BUILD_LZMA
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


static int64_t offtin(uint8_t *buf)
{
    int64_t y;

    y=buf[7]&0x7F;
    y=y*256;y+=buf[6];
    y=y*256;y+=buf[5];
    y=y*256;y+=buf[4];
    y=y*256;y+=buf[3];
    y=y*256;y+=buf[2];
    y=y*256;y+=buf[1];
    y=y*256;y+=buf[0];

    if(buf[7]&0x80) y=-y;

    return y;
}

static int bspatch_write(struct bpak_bspatch_context *ctx,
                        uint8_t *buffer,
                        size_t length)
{
    uint8_t *pp = buffer; // Patch pointer within the current chunk
    int rc = 0;
    size_t bytes_available = length;

process_more:

    switch (ctx->state) {
        case BPAK_PATCH_STATE_FILL_CTRL_BUF:
        {
            if (ctx->ctrl_buf_count < BPAK_BSPATCH_CTRL_BUFFER_LENGTH) {
                size_t needed = BPAK_BSPATCH_CTRL_BUFFER_LENGTH - ctx->ctrl_buf_count;
                size_t bytes_to_copy = BPAK_MIN(bytes_available, needed);
                memcpy(&ctx->ctrl_buf[ctx->ctrl_buf_count], pp, bytes_to_copy);
                bytes_available -= bytes_to_copy;
                ctx->ctrl_buf_count += bytes_to_copy;
                pp += bytes_to_copy;

                if (ctx->ctrl_buf_count == BPAK_BSPATCH_CTRL_BUFFER_LENGTH) {
                    ctx->state = BPAK_PATCH_STATE_READ_CTRL;
                    goto process_more;
                }

            }
        }
        break;
        case BPAK_PATCH_STATE_READ_CTRL:
        {
            ctx->diff_count = offtin(&ctx->ctrl_buf[0]);
            ctx->extra_count = offtin(&ctx->ctrl_buf[8]);
            ctx->adjust = offtin(&ctx->ctrl_buf[16]);

            bpak_printf(2, "Patch: %10li %10li %10li %li\n", ctx->diff_count,
                            ctx->extra_count, ctx->adjust, bytes_available);

            ctx->state = BPAK_PATCH_STATE_APPLY_DIFF;

            if (bytes_available)
                goto process_more;
        }
        break;
        case BPAK_PATCH_STATE_APPLY_DIFF:
        {
            size_t data_to_process = BPAK_MIN(BPAK_MIN(bytes_available,
                                    ctx->diff_count), ctx->patch_buffer_length);

            ctx->diff_count -= data_to_process;
            bytes_available -= data_to_process;

            ssize_t nread = ctx->read_origin(ctx->origin_position,
                                  ctx->patch_buffer, data_to_process,
                                  ctx->user_priv);

            if (nread != data_to_process) {
                bpak_printf(0, "Could not read %li bytes from origin\n",
                                data_to_process);
                ctx->state = BPAK_PATCH_STATE_ERROR;
                if (nread < 0)
                    rc = nread;
                else
                    rc = -BPAK_PATCH_READ_ORIGIN_ERROR;

                break;
            }

            ctx->origin_position += nread;

            for (unsigned int i = 0; i < data_to_process; i++) {
                ctx->patch_buffer[i] += pp[i];
            }

            pp += data_to_process;

            ssize_t nwritten = ctx->write_output(ctx->output_offset + ctx->output_position,
                                             ctx->patch_buffer, data_to_process,
                                             ctx->user_priv);

            if (nwritten != data_to_process) {
                bpak_printf(0, "Could not write to output file\n");
                ctx->state = BPAK_PATCH_STATE_ERROR;

                if (nwritten < 0)
                    rc = nwritten;
                else
                    rc = -BPAK_PATCH_WRITE_ERROR;
                break;
            }

            ctx->output_position += nwritten;

            if (ctx->diff_count == 0) {
                if (ctx->extra_count > 0) {
                    ctx->state = BPAK_PATCH_STATE_APPLY_EXTRA;
                } else {
                    ctx->origin_position += ctx->adjust;
                    ctx->state = BPAK_PATCH_STATE_FILL_CTRL_BUF;
                    ctx->ctrl_buf_count = 0;
                }
            }

            if (bytes_available > 0) {
                goto process_more;
            }
        }
        break;
        case BPAK_PATCH_STATE_APPLY_EXTRA:
        {
            size_t data_to_process = BPAK_MIN(bytes_available,
                                             ctx->extra_count);
            ctx->extra_count -= data_to_process;
            bytes_available -= data_to_process;

            ssize_t nwritten = ctx->write_output(ctx->output_offset + ctx->output_position,
                                      pp, data_to_process,
                                      ctx->user_priv);

            if (nwritten != data_to_process) {
                bpak_printf(0, "Could not write to output file\n");
                ctx->state = BPAK_PATCH_STATE_ERROR;
                if (nwritten < 0)
                    rc = nwritten;
                else
                    rc = -BPAK_PATCH_WRITE_ERROR;
                break;
            }

            ctx->output_position += nwritten;
            pp += data_to_process;

            if (ctx->extra_count == 0) {
                ctx->state = BPAK_PATCH_STATE_FILL_CTRL_BUF;
                ctx->ctrl_buf_count = 0;
                ctx->origin_position += ctx->adjust;

                if (bytes_available > 0) {
                    goto process_more;
                }
            }
        }
        break;
        case BPAK_PATCH_STATE_ERROR:
            bpak_printf(0,"bspatch error\n");
            return -1;
        break;
        default:
            return -1;
    }

    return rc;
}


static int decompressor_init(struct bpak_bspatch_context *ctx)
{
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
            ctx->decompressor_priv = bpak_calloc(sizeof(heatshrink_decoder), 1);

            if (ctx->decompressor_priv == NULL)
                return -BPAK_FAILED;

            heatshrink_decoder_reset((heatshrink_decoder *) ctx->decompressor_priv);
        break;
#ifdef BPAK_BUILD_LZMA
        case BPAK_COMPRESSION_LZMA:
            lzma_stream *strm = bpak_calloc(sizeof(lzma_stream), 1);
            ctx->decompressor_priv = strm;

            if (ctx->decompressor_priv == NULL) {
                return -BPAK_FAILED;
            }

            lzma_ret ret = lzma_stream_decoder(
                    strm, UINT64_MAX, LZMA_CONCATENATED);

            if (ret != LZMA_OK) {
                bpak_printf(0, "lzma init error (%u)\n", ret);
                return -BPAK_FAILED;
            }

            strm->allocator = &lzma_alloc;
        break;
#endif
        default:
            return -BPAK_UNSUPPORTED_COMPRESSION;
    }

    return BPAK_OK;
}

static void decompressor_free(struct bpak_bspatch_context *ctx)
{

    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
            if (ctx->decompressor_priv != NULL) {
                bpak_free(ctx->decompressor_priv);
                ctx->decompressor_priv = NULL;
            }
        break;
#ifdef BPAK_BUILD_LZMA
        case BPAK_COMPRESSION_LZMA:
            if (ctx->decompressor_priv != NULL) {
                lzma_end((lzma_stream *) ctx->decompressor_priv);
                bpak_free(ctx->decompressor_priv);
                ctx->decompressor_priv = NULL;
            }
        break;
#endif
        default:
            return ;
    }
}

#ifdef BPAK_BUILD_LZMA
static int bspatch_lzma_write(struct bpak_bspatch_context *ctx,
                            uint8_t *buffer,
                            size_t length)
{
    int rc;
    lzma_stream *strm = (lzma_stream *) ctx->decompressor_priv;
    lzma_action action;
    uint8_t outbuf[BUFSIZ];

    if (length == 0)
        action = LZMA_FINISH;
    else
        action = LZMA_RUN;

    strm->next_in = buffer;
    strm->avail_in = length;
    strm->next_out = outbuf;
    strm->avail_out = sizeof(outbuf);

    if (action == LZMA_FINISH)
        bpak_printf(2, "lzma finish\n");

    while (strm->avail_in > 0 || action == LZMA_FINISH) {
        lzma_ret ret = lzma_code(strm, action);

        size_t write_size = sizeof(outbuf) - strm->avail_out;

        if (write_size > 0) {
            if (action == LZMA_FINISH)
                bpak_printf(2, "finishing write %zu\n", write_size);
            rc = bspatch_write(ctx, outbuf, write_size);

            if (rc != BPAK_OK) {
                bpak_printf(0, "bspatch failed (%i)\n", rc);
                return rc;
            }

            strm->next_out = outbuf;
            strm->avail_out = sizeof(outbuf);
        }

        if (ret != LZMA_OK) {
            if (ret == LZMA_STREAM_END) {
                bpak_printf(2, "stream end\n");
                return BPAK_OK;
            }
            bpak_printf(0, "lzma: Decoder error: %u\n", ret);
            return -BPAK_FAILED;
        }
    }

    ctx->input_position += length;

    return BPAK_OK;
}
#endif

static int bspatch_hs_write(struct bpak_bspatch_context *ctx,
                            uint8_t *buffer,
                            size_t length)
{
    int rc;
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t sunk = 0;
    HSD_poll_res pres = 0;
    HSD_sink_res sres = 0;
    HSD_finish_res fres = 0;
    heatshrink_decoder *hsd = (heatshrink_decoder *) ctx->decompressor_priv;

    if (ctx->input_position >= ctx->input_length) {
        bpak_printf(0, "Error: Tried to write %lu extra bytes, ignoring\n",
                        length);
        return -1;
    }

    do {
        sres = heatshrink_decoder_sink(hsd, &buffer[sunk],
                                        length - sunk, &sink_sz);

        if (sres < 0)
            return -BPAK_DECOMPRESSOR_ERROR;

        sunk += sink_sz;
        ctx->input_position += sink_sz;

        do {
poll_more:
            pres = heatshrink_decoder_poll(hsd,
                                           ctx->input_buffer,
                                           ctx->input_buffer_length,
                                           &poll_sz);

            if (pres < 0)
                return -BPAK_DECOMPRESSOR_ERROR;

            rc = bspatch_write(ctx, ctx->input_buffer, poll_sz);

            if (rc != BPAK_OK) {
                bpak_printf(0, "bspatch failed (%i)\n", rc);
                return rc;
            }

        } while(pres == HSDR_POLL_MORE);

        if (poll_sz == 0 && (ctx->input_position >= ctx->input_length)) {
            fres = heatshrink_decoder_finish(hsd);

            if (fres == HSDR_FINISH_MORE)
                goto poll_more;
            if (fres < 0)
                return -BPAK_DECOMPRESSOR_ERROR;
        }
    } while(sunk < length);

    return BPAK_OK;
}

int bpak_bspatch_init(struct bpak_bspatch_context *ctx,
                      size_t buffer_length,
                      size_t input_length,
                      bpak_io_t read_origin,
                      bpak_io_t write_output,
                      off_t output_offset,
                      enum bpak_compression compression,
                      void *user_priv)
{
    int rc;

    memset(ctx, 0, sizeof(*ctx));

    ctx->patch_buffer = bpak_calloc(buffer_length, 1);

    if (ctx->patch_buffer == NULL)
        return -BPAK_FAILED;

    ctx->input_buffer = bpak_calloc(buffer_length, 1);

    if (ctx->input_buffer == NULL) {
        bpak_free(ctx->patch_buffer);
        return -BPAK_FAILED;
    }

    ctx->patch_buffer_length = buffer_length;
    ctx->input_buffer_length = buffer_length;

    ctx->read_origin = read_origin;
    ctx->write_output = write_output;
    ctx->compression = compression;
    ctx->input_length = input_length;
    ctx->user_priv = user_priv;
    ctx->output_offset = output_offset;

    rc = decompressor_init(ctx);

    if (rc != BPAK_OK) {
        goto err_free_buffers_out;
    }
    return BPAK_OK;

err_free_buffers_out:
    bpak_free(ctx->input_buffer);
    bpak_free(ctx->patch_buffer);
    return rc;
}

int bpak_bspatch_write(struct bpak_bspatch_context *ctx,
                        uint8_t *buffer,
                        size_t length)
{
    int rc;
    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
            rc = bspatch_write(ctx, buffer, length);
            return rc;
        break;
        case BPAK_COMPRESSION_HS:
            return bspatch_hs_write(ctx, buffer, length);
        break;
#ifdef BPAK_BUILD_LZMA
        case BPAK_COMPRESSION_LZMA:
            return bspatch_lzma_write(ctx, buffer, length);
        break;
#endif
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    return BPAK_OK;
}

ssize_t bpak_bspatch_final(struct bpak_bspatch_context *ctx)
{

    if (ctx->state == BPAK_PATCH_STATE_ERROR)
        return -1;

    switch (ctx->compression) {
        case BPAK_COMPRESSION_NONE:
        break;
        case BPAK_COMPRESSION_HS:
        break;
#ifdef BPAK_BUILD_LZMA
        case BPAK_COMPRESSION_LZMA:
        {
            int rc = bspatch_lzma_write(ctx, NULL, 0);

            if (rc != BPAK_OK)
                return rc;
        }
        break;
#endif
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    return ctx->output_position;
}

void bpak_bspatch_free(struct bpak_bspatch_context *ctx)
{
    bpak_free(ctx->patch_buffer);
    bpak_free(ctx->input_buffer);
    decompressor_free(ctx);
}
