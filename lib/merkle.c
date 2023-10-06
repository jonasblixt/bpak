/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/merkle.h>
#include <bpak/crypto.h>

BPAK_EXPORT ssize_t bpak_merkle_compute_size(size_t input_data_length)
{
    size_t level_length = input_data_length;
    unsigned int level = 0;
    size_t pad_bytes;
    size_t result = 0;

    if (input_data_length % BPAK_MERKLE_BLOCK_SZ != 0)
        return -BPAK_BAD_ALIGNMENT;

    do {
        level_length = (level_length >> BPAK_MERKLE_BLOCK_BITS) * 32;
        pad_bytes = (~level_length + 1) & (BPAK_MERKLE_BLOCK_SZ - 1);
        level_length += pad_bytes;
        result += level_length;
        level = level + 1;

        if (level > BPAK_MERKLE_MAX_LEVELS)
            return -BPAK_NO_SPACE_LEFT;

    } while (level_length != BPAK_MERKLE_BLOCK_SZ);

    return result;
}

BPAK_EXPORT int bpak_merkle_init(struct bpak_merkle_context *ctx,
                                 size_t input_data_length, const uint8_t *salt,
                                 size_t salt_length, bpak_io_t wr, bpak_io_t rd,
                                 off_t offset, bool zero_fill_output,
                                 void *priv)
{
    unsigned int level = 0;
    size_t level_length = 0;
    size_t pad_bytes = 0;

    bpak_printf(2, "%s: input length: %zu\n", __func__, input_data_length);

    memset(ctx, 0, sizeof(*ctx));
    ctx->wr = wr;
    ctx->rd = rd;
    ctx->offset = offset;
    ctx->input_data_length = input_data_length;
    ctx->block_byte_counter = BPAK_MERKLE_BLOCK_SZ;
    ctx->salt_length = salt_length;
    ctx->priv = priv;

    if (input_data_length % BPAK_MERKLE_BLOCK_SZ != 0)
        return -BPAK_BAD_ALIGNMENT;

    if (salt_length > sizeof(ctx->salt))
        return -BPAK_NO_SPACE_LEFT;

    memcpy(ctx->salt, salt, salt_length);

    /* Compute the length of each level and the total length of the hash tree */
    level_length = input_data_length;
    do {
        level_length = (level_length >> BPAK_MERKLE_BLOCK_BITS) * 32;
        pad_bytes = (~level_length + 1) & (BPAK_MERKLE_BLOCK_SZ - 1);
        level_length += pad_bytes;
        ctx->level_length[level] = level_length;
        ctx->hash_tree_length += level_length;
        level = level + 1;

        if (level >= BPAK_MERKLE_MAX_LEVELS)
            return -BPAK_NO_SPACE_LEFT;

    } while (level_length != BPAK_MERKLE_BLOCK_SZ);

    ctx->no_of_levels = level;

    /* Compute offsets for each level */
    off_t tree_level_offset = ctx->hash_tree_length;
    for (unsigned int i = 0; i < ctx->no_of_levels; i++) {
        tree_level_offset -= ctx->level_length[i];
        ctx->level_offset[i] = tree_level_offset;

        bpak_printf(2,
                    "Level %i, length: %zu, offset: %li\n",
                    i,
                    ctx->level_length[i],
                    ctx->level_offset[i]);
    }

    /* Zero fill output tree */
    if (zero_fill_output) {
        bpak_printf(2, "Zero filling tree\n");
        size_t zero_fill_bytes = ctx->hash_tree_length;
        off_t output_offset = offset;
        while (zero_fill_bytes > 0) {
            ssize_t n_written =
                ctx->wr(output_offset, ctx->buffer, sizeof(ctx->buffer), priv);

            if (n_written < 0)
                return n_written;
            if (n_written != sizeof(ctx->buffer))
                return -BPAK_WRITE_ERROR;

            output_offset += n_written;
            zero_fill_bytes -= sizeof(ctx->buffer);
        }
        bpak_printf(2, "Zero fill done\n");
    }

    return BPAK_OK;
}

BPAK_EXPORT size_t bpak_merkle_get_size(struct bpak_merkle_context *ctx)
{
    return ctx->hash_tree_length;
}

BPAK_EXPORT int bpak_merkle_write_chunk(struct bpak_merkle_context *ctx,
                                        uint8_t *buffer, size_t length)
{
    int rc;
    size_t data_to_process = length;
    size_t chunk_length;
    uint8_t *chunk_buffer = buffer;

    while (data_to_process > 0) {
        if (ctx->block_byte_counter == BPAK_MERKLE_BLOCK_SZ) {
            rc = bpak_hash_init(&ctx->running_hash, BPAK_HASH_SHA256);
            if (rc != BPAK_OK)
                return rc;
            rc = bpak_hash_update(&ctx->running_hash,
                                  ctx->salt,
                                  ctx->salt_length);
            if (rc != BPAK_OK)
                goto err_free_hash_ctx_out;
        }

        chunk_length = BPAK_MIN(ctx->block_byte_counter, data_to_process);

        rc = bpak_hash_update(&ctx->running_hash, chunk_buffer, chunk_length);

        if (rc != BPAK_OK)
            goto err_free_hash_ctx_out;

        chunk_buffer += chunk_length;
        ctx->block_byte_counter -= chunk_length;
        data_to_process -= chunk_length;

        if (ctx->block_byte_counter == 0) {
            ctx->block_byte_counter = BPAK_MERKLE_BLOCK_SZ;

            rc = bpak_hash_final(&ctx->running_hash, ctx->buffer, 32, NULL);

            if (rc != BPAK_OK)
                goto err_free_hash_ctx_out;

            bpak_hash_free(&ctx->running_hash);

            off_t output_offset =
                ctx->input_chunk_counter + ctx->level_offset[0];
            ssize_t bytes_written = ctx->wr(ctx->offset + output_offset,
                                            ctx->buffer,
                                            sizeof(ctx->buffer),
                                            ctx->priv);

            if (bytes_written < 0)
                return bytes_written;
            if (bytes_written != sizeof(ctx->buffer))
                return -BPAK_WRITE_ERROR;

            ctx->input_chunk_counter += bytes_written;

            if (ctx->input_data_length == BPAK_MERKLE_BLOCK_SZ) {
                bpak_printf(2, "Early out\n");
                /* Special case when total input bytes == 4096. In this
                 * case the root hash will be the hash of the first and only
                 * input block. */
                ctx->finished = true;
                return BPAK_OK;
            }
        }
    }

    return BPAK_OK;
err_free_hash_ctx_out:
    bpak_hash_free(&ctx->running_hash);
    return rc;
}

BPAK_EXPORT int bpak_merkle_finish(struct bpak_merkle_context *ctx,
                                   bpak_merkle_hash_t roothash)
{
    int rc;
    off_t input_offset, output_offset;
    ssize_t input_block_count;
    ssize_t bytes_to_process;
    ssize_t chunk_length;
    ssize_t n_read;
    ssize_t n_written;

    if (ctx->finished) {
        memcpy(roothash, ctx->buffer, 32);
        return BPAK_OK;
    }

    /* Build the rest of the tree from level 1 and up */
    for (unsigned int i = 1; i < ctx->no_of_levels; i++) {
        input_block_count = ctx->level_length[i - 1] / BPAK_MERKLE_BLOCK_SZ;
        input_offset = ctx->level_offset[i - 1];
        output_offset = ctx->level_offset[i];

        for (int n = 0; n < input_block_count; n++) {
            bpak_printf(2, "Computing block %i on level %i\n", n, i);
            rc = bpak_hash_init(&ctx->running_hash, BPAK_HASH_SHA256);
            if (rc != BPAK_OK)
                return rc;

            rc = bpak_hash_update(&ctx->running_hash,
                                  ctx->salt,
                                  ctx->salt_length);
            if (rc != BPAK_OK)
                goto err_free_hash_ctx_out;

            /* Read sizof(ctx->buffer) sized chunks and update hash for block
             *  n */
            for (unsigned int c = 0; c < BPAK_MERKLE_BLOCK_SZ;
                 c += sizeof(ctx->buffer)) {
                n_read = ctx->rd(ctx->offset + input_offset + c,
                                 ctx->buffer,
                                 sizeof(ctx->buffer),
                                 ctx->priv);
                if (n_read < 0) {
                    rc = n_read;
                    goto err_free_hash_ctx_out;
                }
                if (n_read != sizeof(ctx->buffer)) {
                    rc = -BPAK_READ_ERROR;
                    goto err_free_hash_ctx_out;
                }

                rc = bpak_hash_update(&ctx->running_hash,
                                      ctx->buffer,
                                      sizeof(ctx->buffer));

                if (rc != BPAK_OK)
                    goto err_free_hash_ctx_out;
            }

            rc = bpak_hash_final(&ctx->running_hash, ctx->buffer, 32, NULL);

            if (rc != BPAK_OK)
                goto err_free_hash_ctx_out;

            n_written = ctx->wr(ctx->offset + output_offset,
                                ctx->buffer,
                                sizeof(ctx->buffer),
                                ctx->priv);

            if (n_written < 0) {
                rc = n_written;
                goto err_free_hash_ctx_out;
            }
            if (n_written != sizeof(ctx->buffer)) {
                rc = -BPAK_WRITE_ERROR;
                goto err_free_hash_ctx_out;
            }

            output_offset += n_written;
            input_offset += BPAK_MERKLE_BLOCK_SZ;
        }
    }

    bpak_hash_free(&ctx->running_hash);
    /* Compute the root hash, which is the hash of the top level */
    bpak_printf(2, "Computing root hash\n");
    rc = bpak_hash_init(&ctx->running_hash, BPAK_HASH_SHA256);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_hash_update(&ctx->running_hash, ctx->salt, ctx->salt_length);

    if (rc != BPAK_OK)
        goto err_free_hash_ctx_out;

    bytes_to_process = ctx->level_length[ctx->no_of_levels - 1];
    input_offset = ctx->level_offset[ctx->no_of_levels - 1];
    while (bytes_to_process > 0) {
        chunk_length = BPAK_MIN((ssize_t)sizeof(ctx->buffer), bytes_to_process);
        n_read = ctx->rd(ctx->offset + input_offset,
                         ctx->buffer,
                         chunk_length,
                         ctx->priv);

        if (n_read < 0) {
            rc = n_read;
            goto err_free_hash_ctx_out;
        }
        if (n_read != chunk_length) {
            rc = -BPAK_READ_ERROR;
            goto err_free_hash_ctx_out;
        }

        rc = bpak_hash_update(&ctx->running_hash, ctx->buffer, chunk_length);
        if (rc != BPAK_OK)
            goto err_free_hash_ctx_out;
        bytes_to_process -= chunk_length;
        input_offset += chunk_length;
    }

    rc = bpak_hash_final(&ctx->running_hash, roothash, 32, NULL);
    ctx->finished = true;

err_free_hash_ctx_out:
    bpak_hash_free(&ctx->running_hash);
    return rc;
}
