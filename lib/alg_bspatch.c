#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>

enum bspatch_state
{
    PATCH_STATE_FILL_CTRL_BUF,
    PATCH_STATE_READ_CTRL,
    PATCH_STATE_APPLY_DIFF,
    PATCH_STATE_APPLY_EXTRA,
    PATCH_STATE_FINISH,
    PATCH_STATE_ERROR,
};

struct bpak_bspatch_private
{
    uint8_t buffer[4096];
    uint8_t patch_buffer[4096];
    int64_t diff_sz;
    int64_t extra_sz;
    int64_t adjust;
    int64_t new_size;
    int64_t new_pos;
    int64_t old_pos;
    int64_t old_size;
    size_t patch_size;
    int64_t patch_count;
    int64_t patch_pos;
    uint8_t ctrl_buf[24];
    uint8_t ctrl_buf_count;
    enum bspatch_state state;
    struct bpak_io compressor_io;
    uint8_t compressor_buffer[1024*16];
    struct bpak_alg_instance compressor;
    struct bpak_header oh, nh;
    struct bpak_part_header *op, *np;
    struct bpak_io *in;
    struct bpak_io *out;
    struct bpak_io *origin;
};

#define BSPATCH_PRIVATE(__ins) ((struct bpak_bspatch_private *) (__ins)->state)

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


static size_t compressor_write(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_alg_instance *ins = (struct bpak_alg_instance *) io->priv;
    struct bpak_bspatch_private *p = BSPATCH_PRIVATE(ins);
    uint8_t *pp = (uint8_t *) ptr;
    uint8_t buf[8];
    size_t bytes_available = size;
    int rc;

process_more:

    switch (p->state)
    {
        case PATCH_STATE_FILL_CTRL_BUF:
        {
            if (p->ctrl_buf_count < 24)
            {
                size_t needed = 24 - p->ctrl_buf_count;
                size_t bytes_to_copy = BPAK_MIN(bytes_available, needed);
                memcpy(&p->ctrl_buf[p->ctrl_buf_count], pp, bytes_to_copy);
                bytes_available -= bytes_to_copy;
                p->ctrl_buf_count += bytes_to_copy;
                pp += bytes_to_copy;

                if (p->ctrl_buf_count == 24)
                {
                    p->state = PATCH_STATE_READ_CTRL;
                    goto process_more;
                }

            }
        }
        break;
        case PATCH_STATE_READ_CTRL:
        {
            memcpy(buf, &p->ctrl_buf[0], 8);
            p->diff_sz = offtin(buf);
            memcpy(buf, &p->ctrl_buf[8], 8);
            p->extra_sz = offtin(buf);
            memcpy(buf, &p->ctrl_buf[16], 8);
            p->adjust = offtin(buf);

            bpak_printf(2, "Patch: %10li %10li %10li %li\n", p->diff_sz,
                            p->extra_sz, p->adjust, bytes_available);


            p->state = PATCH_STATE_APPLY_DIFF;
            p->patch_pos = p->diff_sz;

            if (bytes_available)
                goto process_more;
        }
        break;
        case PATCH_STATE_APPLY_DIFF:
        {
            size_t data_to_process = BPAK_MIN(bytes_available, p->patch_pos);

            p->patch_pos -= data_to_process;
            bytes_available -= data_to_process;

            rc = bpak_io_read(p->origin, p->patch_buffer, data_to_process);

            if (rc != data_to_process)
            {
                bpak_printf(0, "Could not read %li bytes from origin\n",
                                data_to_process);
                p->state = PATCH_STATE_ERROR;
                break;
            }

            for (int i = 0; i < data_to_process; i++)
            {
                p->patch_buffer[i] += pp[i];
            }

            pp += data_to_process;

            rc = bpak_io_write(p->out, p->patch_buffer, data_to_process);

            if (rc != data_to_process)
            {
                bpak_printf(0, "Could not write to output file\n");
                p->state = PATCH_STATE_ERROR;
                break;
            }

            ins->output_size += data_to_process;

            if (!p->patch_pos)
            {
                if (p->extra_sz)
                {
                    p->state = PATCH_STATE_APPLY_EXTRA;
                    p->patch_pos = p->extra_sz;
                }
                else
                {
                    rc = bpak_io_seek(p->origin, p->adjust, BPAK_IO_SEEK_FWD);

                    if (rc != BPAK_OK)
                    {
                        p->state = PATCH_STATE_ERROR;
                        bpak_printf(0, "Could not seek %li %i\n",
                                            p->adjust, rc);
                        break;
                    }
                    p->state = PATCH_STATE_FILL_CTRL_BUF;
                    p->patch_pos = 0;
                    p->ctrl_buf_count = 0;
                }

                if (bytes_available)
                    goto process_more;
            }
        }
        break;
        case PATCH_STATE_APPLY_EXTRA:
        {
            size_t data_to_process = BPAK_MIN(bytes_available, p->patch_pos);
            p->patch_pos -= data_to_process;
            bytes_available -= data_to_process;

            rc = bpak_io_write(p->out, pp, data_to_process);

            if (rc != data_to_process)
            {
                bpak_printf(0, "Could not write to output file\n");
                p->state = PATCH_STATE_ERROR;
                break;
            }

            pp += data_to_process;
            ins->output_size += data_to_process;

            if (!p->patch_pos)
            {
                p->state = PATCH_STATE_FILL_CTRL_BUF;
                p->patch_pos = 0;
                p->ctrl_buf_count = 0;

                rc = bpak_io_seek(p->origin, p->adjust, BPAK_IO_SEEK_FWD);

                if (rc != BPAK_OK)
                {
                    p->state = PATCH_STATE_ERROR;
                    bpak_printf(0, "Could not seek %li %i\n", p->adjust, rc);
                    break;
                }

                if (bytes_available)
                    goto process_more;
            }
        }
        break;
        case PATCH_STATE_FINISH:
        break;
        case PATCH_STATE_ERROR:
        break;
        default:
            return -1;
    }

    return size;
}


static size_t compressor_read(struct bpak_io *io, void *ptr, size_t size)
{
    struct bpak_alg_instance *ins = (struct bpak_alg_instance *) io->priv;
    struct bpak_bspatch_private *p = BSPATCH_PRIVATE(ins);
    size_t data_to_read;
    size_t r;

    data_to_read = BPAK_MIN(size, p->patch_count);

    if (data_to_read <= 0)
        return 0;

    r = bpak_io_read(p->in, ptr, data_to_read);
    p->patch_count -= r;
    return r;
}

static int bpak_alg_bspatch_init(struct bpak_alg_instance *ins,
                                    struct bpak_io *in,
                                    struct bpak_io *out,
                                    struct bpak_io *origin)
{
    struct bpak_bspatch_private *p = BSPATCH_PRIVATE(ins);
    int rc;

    memset(p, 0, sizeof(*p));
    ins->done = false;

    p->in = in;
    p->out = out;
    p->origin = origin;

    if (ins->origin_header_pos == BPAK_HEADER_POS_LAST)
    {
        rc = bpak_io_seek(origin, sizeof(struct bpak_header), BPAK_IO_SEEK_END);

        if (rc != BPAK_OK)
            return rc;
    }

    rc = bpak_io_read(origin, &p->oh, sizeof(p->oh));

    if (rc != sizeof(p->oh))
    {
        return -BPAK_FAILED;
    }

    if (ins->origin_header_pos == BPAK_HEADER_POS_LAST)
    {
        rc = bpak_io_seek(origin, 0, BPAK_IO_SEEK_SET);

        if (rc != BPAK_OK)
            return rc;
    }

    rc = bpak_valid_header(&p->oh);

    if (rc != BPAK_OK)
    {
        return rc;
    }

    bpak_printf(1, "bspatch init, part: %x, %li (%li), %li\n",
                        ins->part->id,
                        bpak_part_size(ins->part),
                        ins->part->size,
                        bpak_part_offset(ins->header, ins->part));

    p->patch_size = bpak_part_size(ins->part);
    p->patch_count = bpak_part_size(ins->part);
    p->new_size = ins->part->size;

    bpak_printf(2, "Read origin header\n");
    rc = bpak_get_part(&p->oh, ins->part->id, &p->op);

    if (rc != BPAK_OK)
        return rc;

    bpak_printf(2, "Found origin part, %li %li\n", bpak_part_size(p->op),
                                        bpak_part_offset(&p->oh, p->op));

    rc = bpak_io_init(&p->compressor_io, ins);

    if (rc != BPAK_OK)
        return rc;

    p->compressor_io.on_read = compressor_read;
    p->compressor_io.on_write = compressor_write;
/*
    bpak_printf(2, "Seeking to %li\n",
                        bpak_part_offset(ins->header, ins->part));

    rc = bpak_io_seek(p->in, bpak_part_offset(ins->header, ins->part),
                    BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Failed to seek\n");
        return rc;
    }
*/
    rc = bpak_alg_init(&p->compressor, ins->alg->parameter,
                        ins->part, ins->header,
                        p->compressor_buffer, sizeof(p->compressor_buffer),
                        &p->compressor_io, &p->compressor_io, NULL);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not initialize compressor (%x)\n",
                        ins->alg->parameter);
        return rc;
    }


    uint64_t out_pos = bpak_io_tell(p->out);

    memset(p->buffer, 0, sizeof(p->buffer));

    for (int i = 0; i < ins->part->size/sizeof(p->buffer); i++)
        bpak_io_write(p->out, p->buffer, sizeof(p->buffer));

    bpak_io_seek(p->out, out_pos, BPAK_IO_SEEK_SET);


    bpak_printf(2, "origin pos: %li\n", bpak_io_tell(p->origin));
    return BPAK_OK;
}

static int bpak_alg_bspatch_process(struct bpak_alg_instance *ins)
{
    struct bpak_bspatch_private *p = BSPATCH_PRIVATE(ins);
    int rc;

    if (bpak_alg_done(&p->compressor))
    {
        ins->done = true;
        return BPAK_OK;
    }

    return bpak_alg_process(&p->compressor);
}

static const struct bpak_alg bspatch_alg =
{
    .id = 0xb5964388, /* id("bspatch") */
    .name = "bspatch",
    .parameter = 0x5f9bc012, /* id("heatshrink-decode") */
    .on_init = bpak_alg_bspatch_init,
    .on_process = bpak_alg_bspatch_process,
    .state_size = sizeof(struct bpak_bspatch_private),
};

int bpak_alg_bspatch_register(void)
{
    return bpak_alg_register(&bspatch_alg);
}
