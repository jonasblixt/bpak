#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/bspatch.h>
#include <bpak/bspatch_hs.h>
#include <bpak/heatshrink_decoder.h>

int bpak_bspatch_hs_init(struct bpak_bspatch_hs_context *hs_ctx,
                      uint8_t *buffer,
                      size_t buffer_length,
                      size_t patch_length,
                      bpak_io_t read_origin,
                      bpak_io_t write_output,
                      void *user_priv)
{
    memset(hs_ctx, 0, sizeof(*hs_ctx));
    hs_ctx->patch_input_length = patch_length;

    heatshrink_decoder_reset(&hs_ctx->hs);

    return bpak_bspatch_init(&hs_ctx->bspatch_ctx,
                             buffer,
                             buffer_length,
                             read_origin,
                             write_output,
                             user_priv);
}

ssize_t bpak_bspatch_hs_final(struct bpak_bspatch_hs_context *hs_ctx)
{
    return bpak_bspatch_final(&hs_ctx->bspatch_ctx);
}

void bpak_bspatch_hs_free(struct bpak_bspatch_hs_context *hs_ctx)
{
    bpak_bspatch_free(&hs_ctx->bspatch_ctx);
}

int bpak_bspatch_hs_write(struct bpak_bspatch_hs_context *hs_ctx,
                                          uint8_t *buffer,
                                          size_t length)
{
    int rc = BPAK_OK;
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t sunk = 0;
    HSD_poll_res pres = 0;
    HSD_sink_res sres = 0;
    HSD_finish_res fres = 0;
    struct bpak_bspatch_context *ctx = &hs_ctx->bspatch_ctx;

    if (hs_ctx->patch_input_position >= hs_ctx->patch_input_length) {
        bpak_printf(0, "Error: Tried to write %lu extra bytes, ignoring\n",
                        length);
        return -1;
    }

    do {
        sres = heatshrink_decoder_sink(&hs_ctx->hs, &buffer[sunk],
                                        length - sunk, &sink_sz);

        if (sres < 0)
            return -BPAK_DECOMPRESSOR_ERROR;

        sunk += sink_sz;
        hs_ctx->patch_input_position += sink_sz;

        do {
poll_more:
            pres = heatshrink_decoder_poll(&hs_ctx->hs,
                                           ctx->input_buffer,
                                           ctx->input_buffer_length,
                                           &poll_sz);

            if (pres < 0)
                return -BPAK_DECOMPRESSOR_ERROR;

            /* Data is written directly into the internal bspatch buffer,
             *   set the *buffer parameter to NULL
             */
            rc = bpak_bspatch_write(ctx, NULL, poll_sz);

            if (rc != BPAK_OK) {
                bpak_printf(0, "bspatch failed (%i)\n", rc);
                return rc;
            }
        } while(pres == HSDR_POLL_MORE);

        if (poll_sz == 0 && (hs_ctx->patch_input_position >= hs_ctx->patch_input_length)) {
            fres = heatshrink_decoder_finish(&hs_ctx->hs);

            if (fres == HSDR_FINISH_MORE)
                goto poll_more;
            if (fres < 0)
                return -BPAK_DECOMPRESSOR_ERROR;
        }
    } while(sunk < length);

    return BPAK_OK;
}
