#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/bspatch.h>

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

int bpak_bspatch_init(struct bpak_bspatch_context *ctx,
                      uint8_t *buffer,
                      size_t buffer_length,
                      bpak_io_t read_origin,
                      bpak_io_t write_output,
                      void *user_priv)
{
    if (buffer_length % 2 != 0)
        return -BPAK_SIZE_ERROR;

    memset(ctx, 0, sizeof(*ctx));

    ctx->patch_buffer = buffer;
    ctx->patch_buffer_length = buffer_length/2;
    ctx->input_buffer = &buffer[buffer_length/2];
    ctx->input_buffer_length = buffer_length/2;
    ctx->read_origin = read_origin;
    ctx->write_output = write_output;
    ctx->user_priv = user_priv;

    return 0;
}

int bpak_bspatch_write(struct bpak_bspatch_context *ctx,
                        uint8_t *buffer,
                        size_t length)
{
    uint8_t *pp = NULL; // Patch pointer within the current chunk
    int rc = 0;
    size_t bytes_available = length;

    if (buffer != NULL)
        pp = buffer;
    else
        pp = ctx->input_buffer;

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

            if (data_to_process <= 0)
                break;

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

            ssize_t nwritten = ctx->write_output(ctx->output_position,
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

            if (ctx->diff_count <= 0) {
                if (ctx->extra_count > 0) {
                    ctx->state = BPAK_PATCH_STATE_APPLY_EXTRA;
                } else {
                    ctx->origin_position += ctx->adjust;
                    ctx->state = BPAK_PATCH_STATE_FILL_CTRL_BUF;
                    ctx->ctrl_buf_count = 0;
                }
            }

            if (bytes_available)
                goto process_more;
        }
        break;
        case BPAK_PATCH_STATE_APPLY_EXTRA:
        {
            size_t data_to_process = BPAK_MIN(bytes_available,
                                             ctx->extra_count);
            ctx->extra_count -= data_to_process;
            bytes_available -= data_to_process;

            ssize_t nwritten = ctx->write_output(ctx->output_position,
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

            if (ctx->extra_count <= 0) {
                ctx->state = BPAK_PATCH_STATE_FILL_CTRL_BUF;
                ctx->ctrl_buf_count = 0;
                ctx->origin_position += ctx->adjust;

                if (bytes_available)
                    goto process_more;
            }
        }
        break;
        case BPAK_PATCH_STATE_ERROR:
            return -1;
        break;
        default:
            return -1;
    }

    return rc;
}

ssize_t bpak_bspatch_final(struct bpak_bspatch_context *ctx)
{
    if (ctx->state == BPAK_PATCH_STATE_ERROR)
        return -1;
    return ctx->output_position;
}

int bpak_bspatch_free(struct bpak_bspatch_context *ctx)
{
    (void) ctx;
    return 0;
}
