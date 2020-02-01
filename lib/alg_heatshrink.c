#include <string.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>

#include "heatshrink/heatshrink_encoder.h"
#include "heatshrink/heatshrink_decoder.h"

#ifndef BPAK_HSE_BUF_SZ
    #define BPAK_HSE_BUF_SZ 4096
#endif

#ifndef BPAK_HSD_BUF_SZ
    #define BPAK_HSD_BUF_SZ 4096
#endif

struct bpak_alg_hse_state
{
    heatshrink_encoder hse;
    uint8_t in_buf[BPAK_HSE_BUF_SZ];
    uint8_t out_buf[BPAK_HSE_BUF_SZ];
    uint64_t bytes_to_process;
    struct bpak_io *in;
    struct bpak_io *out;
    struct bpak_io *origin;
};

struct bpak_alg_hsd_state
{
    heatshrink_decoder hsd;
    uint8_t in_buf[BPAK_HSD_BUF_SZ];
    uint8_t out_buf[BPAK_HSD_BUF_SZ];
    uint64_t bytes_to_process;
    struct bpak_io *in;
    struct bpak_io *out;
    struct bpak_io *origin;
};

static int bpak_alg_hse_init(struct bpak_alg_instance *ins,
                                struct bpak_io *in,
                                struct bpak_io *out,
                                struct bpak_io *origin)

{
    struct bpak_alg_hse_state *s = (struct bpak_alg_hse_state *) ins->state;
    memset(s, 0, sizeof(*s));
    heatshrink_encoder_reset(&(s->hse));

    if (ins->part)
        s->bytes_to_process = ins->part->size;

    s->in = in;
    s->out = out;
    return BPAK_OK;
}

static int bpak_alg_hse_process(struct bpak_alg_instance *ins)
{
    int rc = BPAK_OK;
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t chunk_sz = 0;
    size_t sunk = 0;
    struct bpak_alg_hse_state *s = (struct bpak_alg_hse_state *) ins->state;
    HSE_poll_res pres = 0;
    HSE_sink_res sres = 0;
    HSE_finish_res fres = 0;

    if (ins->part)
    {
        chunk_sz = (s->bytes_to_process > BPAK_HSE_BUF_SZ)?  \
                                BPAK_HSE_BUF_SZ:s->bytes_to_process;
    }
    else
    {
        chunk_sz = BPAK_HSE_BUF_SZ;
    }

    chunk_sz = bpak_io_read(s->in, s->in_buf, chunk_sz);

    if (ins->part)
        s->bytes_to_process -= chunk_sz;

    if (chunk_sz == -1)
        chunk_sz = 0;

    memset(s->out_buf, 0, BPAK_HSE_BUF_SZ);
    sunk = 0;

    do
    {
        if (chunk_sz > 0)
        {
            sres = heatshrink_encoder_sink(&s->hse, &s->in_buf[sunk],
                                            chunk_sz - sunk, &sink_sz);

            if (sres < 0)
                return -BPAK_FAILED;

            sunk += sink_sz;

        }

        do
        {
            pres = heatshrink_encoder_poll(&s->hse, s->out_buf, BPAK_HSE_BUF_SZ,
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_FAILED;

            bpak_io_write(s->out, s->out_buf, poll_sz);
            ins->output_size += poll_sz;

        } while(pres == HSER_POLL_MORE);

        if (poll_sz == 0 && chunk_sz == 0)
        {
            fres = heatshrink_encoder_finish(&s->hse);

            if (fres < 0)
                return -BPAK_FAILED;

            if (fres == HSER_FINISH_DONE)
                ins->done = true;
        }

    } while(sunk < chunk_sz);

    return rc;
}


static int bpak_alg_hsd_init(struct bpak_alg_instance *ins,
                                struct bpak_io *in,
                                struct bpak_io *out,
                                struct bpak_io *origin)
{
    struct bpak_alg_hsd_state *s = (struct bpak_alg_hsd_state *) ins->state;
    memset(s, 0, sizeof(*s));
    heatshrink_decoder_reset(&(s->hsd));
    s->bytes_to_process = ins->part->transport_size;

    s->in = in;
    s->out = out;
    return BPAK_OK;
}

static int bpak_alg_hsd_process(struct bpak_alg_instance *ins)
{
    int rc = BPAK_OK;
    size_t sink_sz = 0;
    size_t poll_sz = 0;
    size_t chunk_sz = 0;
    size_t sunk = 0;
    struct bpak_alg_hsd_state *s = (struct bpak_alg_hsd_state *) ins->state;
    HSD_poll_res pres = 0;
    HSD_sink_res sres = 0;
    HSD_finish_res fres = 0;

    chunk_sz = (s->bytes_to_process > BPAK_HSD_BUF_SZ)?  \
                            BPAK_HSD_BUF_SZ:s->bytes_to_process;

    chunk_sz = bpak_io_read(s->in, s->in_buf, chunk_sz);
    s->bytes_to_process -= chunk_sz;

    if (chunk_sz == 0)
    {
        fres = heatshrink_decoder_finish(&s->hsd);

        if (fres == HSDR_FINISH_DONE)
        {
            ins->done = true;
            return BPAK_OK;
        }
    }

    memset(s->out_buf, 0, BPAK_HSD_BUF_SZ);
    sunk = 0;

    do
    {
        if (chunk_sz > 0)
        {
            sres = heatshrink_decoder_sink(&s->hsd, &s->in_buf[sunk],
                                            chunk_sz - sunk, &sink_sz);

            if (sres < 0)
                return -BPAK_FAILED;

            sunk += sink_sz;
        }

        do
        {
            pres = heatshrink_decoder_poll(&s->hsd, s->out_buf, BPAK_HSD_BUF_SZ,
                                            &poll_sz);

            if (pres < 0)
                return -BPAK_FAILED;

            bpak_io_write(s->out, s->out_buf, poll_sz);
            ins->output_size += poll_sz;

        } while(pres == HSDR_POLL_MORE);

        if (poll_sz == 0 && chunk_sz == 0)
        {
            fres = heatshrink_decoder_finish(&s->hsd);

            if (fres < 0)
                return -BPAK_FAILED;

            if (fres == HSDR_FINISH_DONE)
                ins->done = true;
        }

    } while(sunk < chunk_sz);

    return rc;
}

BPAK_ALG(heatshrink_encode)
{
    .id = 0xe31722a6, /* id("heatshrink-encode") */
    .name = "heatshrink-encode",
    .on_init = bpak_alg_hse_init,
    .on_process = bpak_alg_hse_process,
    .state_size = sizeof(struct bpak_alg_hse_state),
};

BPAK_ALG(heatshrink_decode)
{
    .id = 0x5f9bc012, /* id("heatshrink-decode") */
    .name = "heatshrink-decode",
    .on_init = bpak_alg_hsd_init,
    .on_process = bpak_alg_hsd_process,
    .state_size = sizeof(struct bpak_alg_hsd_state),
};

