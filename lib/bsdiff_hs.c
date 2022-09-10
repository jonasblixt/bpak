#include <string.h>
#include <bpak/bsdiff_hs.h>

static ssize_t compressor_write(off_t offset,
                                uint8_t *buffer,
                                size_t length,
                                void *user_priv)
{
    struct bpak_bsdiff_hs_context *ctx_hs =
                (struct bpak_bsdiff_hs_context *) user_priv;
    unsigned char output_buffer[4096];
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t sunk = 0;
    HSE_poll_res pres = 0;
    HSE_sink_res sres = 0;

    do {
        if (length > 0) {
            sres = heatshrink_encoder_sink(&ctx_hs->hse, &buffer[sunk],
                                            length - sunk, &sink_sz);

            if (sres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            sunk += sink_sz;
        }

        do {
            pres = heatshrink_encoder_poll(&ctx_hs->hse, output_buffer,
                                           sizeof(output_buffer),
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            if (poll_sz > 0) {
                ctx_hs->write_output(ctx_hs->output_pos,
                                     output_buffer, poll_sz, ctx_hs->user_priv);
                ctx_hs->output_pos += poll_sz;
            }
        } while(pres == HSER_POLL_MORE);

    } while(sunk < length);

    return sunk;
}

int bpak_bsdiff_hs_init(struct bpak_bsdiff_hs_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      void *user_priv)
{
    memset(ctx, 0, sizeof(*ctx));
    heatshrink_encoder_reset(&(ctx->hse));
    ctx->write_output = write_output;
    ctx->user_priv = user_priv;

    return bpak_bsdiff_init(&ctx->bsdiff_ctx,
                            origin_data,
                            origin_length,
                            new_data,
                            new_length,
                            compressor_write,
                            ctx);
}

int bpak_bsdiff_hs(struct bpak_bsdiff_hs_context *ctx)
{
    int rc;
    uint8_t output_buffer[4096];
    size_t poll_sz = 0;
    HSE_poll_res pres = 0;
    HSE_finish_res fres = 0;

    rc = bpak_bsdiff(&ctx->bsdiff_ctx);

    if (rc != BPAK_OK)
        return rc;

    do {
        fres = heatshrink_encoder_finish(&ctx->hse);

        if (fres < 0)
            return -BPAK_COMPRESSOR_ERROR;

        if (fres == HSER_FINISH_MORE) {
            pres = heatshrink_encoder_poll(&ctx->hse, output_buffer,
                                           sizeof(output_buffer),
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_COMPRESSOR_ERROR;

            if (poll_sz > 0) {
                ctx->write_output(ctx->output_pos, output_buffer, poll_sz,
                                        ctx->user_priv);
                ctx->output_pos += poll_sz;
            }
        }
    } while (fres == HSER_FINISH_MORE);

    return BPAK_OK;
}

int bpak_bsdiff_hs_free(struct bpak_bsdiff_hs_context *ctx)
{
    return bpak_bsdiff_free(&ctx->bsdiff_ctx);
}
