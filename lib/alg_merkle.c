#include <string.h>
#include <stdlib.h>
#include <bpak/bpak.h>
#include <bpak/merkle.h>
#include <bpak/alg.h>
#include <bpak/crc.h>

struct bpak_alg_merkle_ctx
{
    struct bpak_merkle_context merkle;
    struct bpak_io *out;
    size_t pos;
    struct bpak_part_header *p_fs;
    struct bpak_part_header *hash_tree;
    bpak_merkle_hash_t salt;
    uint64_t output_size;
    uint64_t bytes_to_process;
    uint8_t buf[4096];
    enum bpak_header_pos origin_header_pos;
    enum bpak_header_pos out_header_pos;
};

static int merkle_wr(struct bpak_merkle_context *ctx,
                        uint64_t offset,
                        uint8_t *buf,
                        size_t size,
                        void *priv)
{
    struct bpak_alg_merkle_ctx *s = (struct bpak_alg_merkle_ctx *) priv;
    int rc;
    off_t off = s->hash_tree->offset + offset;

    if (s->out_header_pos == BPAK_HEADER_POS_LAST) {
        off -= 4096;
    }

    rc = bpak_io_seek(s->out, off, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    size_t written = bpak_io_write(s->out, buf, size);

    s->output_size += size;

    if (written != size)
        return -BPAK_FAILED;
    return BPAK_OK;
}

static int merkle_rd(struct bpak_merkle_context *ctx,
                        uint64_t offset,
                        uint8_t *buf,
                        size_t size,
                        void *priv)
{
    struct bpak_alg_merkle_ctx *s = (struct bpak_alg_merkle_ctx *) priv;
    int rc;
    off_t off = s->hash_tree->offset + offset;

    if (s->out_header_pos == BPAK_HEADER_POS_LAST) {
        off -= 4096;
    }

    rc = bpak_io_seek(s->out, off, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    size_t read_b = bpak_io_read(s->out, buf, size);

    if (read_b != size)
        return -BPAK_FAILED;
    return BPAK_OK;
}

static int bpak_alg_merkle_init(struct bpak_alg_instance *ins,
                                    struct bpak_io *in,
                                    struct bpak_io *out,
                                    struct bpak_io *origin)
{
    struct bpak_alg_merkle_ctx *ctx = (struct bpak_alg_merkle_ctx *) ins->state;
    uint32_t fs_id = 0;
    int rc;

    memset(ctx, 0, sizeof(*ctx));
    ctx->out = out;
    ctx->origin_header_pos = ins->origin_header_pos;
    ctx->out_header_pos = ins->out_header_pos;

    bpak_printf(2, "merkle init\n");

    bpak_foreach_part(ins->header, p)
    {
        if (bpak_crc32(p->id, "-hash-tree", 10) == ins->part->id)
        {
            fs_id = p->id;
            break;
        }
    }

    if (!fs_id)
    {
        bpak_printf(0, "Error: could not find hash tree\n");
        return -BPAK_FAILED;
    }
    /* Get filesystem header */
    rc = bpak_get_part(ins->header, fs_id, &ctx->p_fs);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not read filesystem header\n");
        return rc;
    }

    /* Get hash tree header */
    rc = bpak_get_part(ins->header, ins->part->id, &ctx->hash_tree);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not read hash tree header\n");
        return rc;
    }

    /* Load salt */
    uint8_t *salt_ptr = NULL;   /*  id("merkle-salt") */
    rc = bpak_get_meta_with_ref(ins->header,  0x7c9b2f93, fs_id,
                                     (void **) &salt_ptr);

    if (rc != BPAK_OK)
        return rc;

    memcpy(ctx->salt, salt_ptr, sizeof(bpak_merkle_hash_t));
    ctx->bytes_to_process = ctx->p_fs->size;

    /* Prepare space for the hash tree */
    off_t offset = ctx->p_fs->offset + ctx->p_fs->size;

    if (ins->out_header_pos == BPAK_HEADER_POS_LAST) {
        offset -= 4096;
    }

    rc = bpak_io_seek(ctx->out, offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: could not seek to fs (%li) \n", __func__, offset);
        return rc;
    }
    char c = 0;
    for (int i = 0; i < ctx->hash_tree->size; i++)
    {
        rc = bpak_io_write(ctx->out, &c, 1);
        if (rc != 1)
            return -BPAK_FAILED;
    }

    /* Position input stream at the begining of the filesystem */

    offset = ctx->p_fs->offset;

    if (ins->out_header_pos == BPAK_HEADER_POS_LAST) {
        offset -= 4096;
    }

    bpak_printf(2, "alg_merkle: seek ctx->out to %li\n", offset);

    rc = bpak_io_seek(ctx->out, offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not seek\n");
        return rc;
    }


    bpak_printf(2, "alg_merkle init done\n");

    return bpak_merkle_init(&ctx->merkle, ctx->p_fs->size, ctx->salt,
                                merkle_wr, merkle_rd, ctx);
}

static int bpak_alg_merkle_process(struct bpak_alg_instance *ins)
{
    struct bpak_alg_merkle_ctx *ctx = (struct bpak_alg_merkle_ctx *) ins->state;
    size_t chunk_sz;
    off_t offset;
    int rc;

    rc = BPAK_OK;

    if (bpak_merkle_done(&ctx->merkle)) {
        bpak_printf(2, "%s: done\n", __func__);
        return BPAK_OK;
    }

    if (ctx->bytes_to_process)
    {
        offset = ctx->p_fs->offset + ctx->pos;

        if (ins->out_header_pos == BPAK_HEADER_POS_LAST) {
            offset -= 4096;
        }

        rc = bpak_io_seek(ctx->out, offset, BPAK_IO_SEEK_SET);

        if (rc != BPAK_OK)
        {
            bpak_printf(0, "Error: seek\n");
            return rc;
        }

        chunk_sz = bpak_io_read(ctx->out, ctx->buf, sizeof(ctx->buf));

        ctx->pos += chunk_sz;

        if (chunk_sz)
        {
            ctx->bytes_to_process -= chunk_sz;

            rc = bpak_merkle_process(&ctx->merkle, ctx->buf, chunk_sz);
        }
    }
    else
    {
        rc = bpak_merkle_process(&ctx->merkle, NULL, 0);
        bpak_printf(2, "%s: merkle_process(...) = %i\n", __func__, rc);
    }

    if (bpak_merkle_done(&ctx->merkle))
    {
        bpak_printf(2, "%s: Alg done\n", __func__);
        ins->done = true;
        ins->output_size = ctx->output_size;

        bpak_merkle_hash_t hash;

        rc = bpak_merkle_out(&ctx->merkle, hash);

        return BPAK_OK;
    }
    return rc;
}

static bool bpak_alg_merkle_needs_more_data(struct bpak_alg_instance *ins)
{
    return false;
}

static const struct bpak_alg merkle_generate_alg =
{
    .id = 0xb5bcc58f, /* id("merkle-generate") */
    .name = "merkle-generate",
    .on_init = bpak_alg_merkle_init,
    .on_process = bpak_alg_merkle_process,
    .on_needs_more_data = bpak_alg_merkle_needs_more_data,
    .state_size = sizeof(struct bpak_alg_merkle_ctx),
};

int bpak_alg_merkle_register(void)
{
    return bpak_alg_register(&merkle_generate_alg);
}
