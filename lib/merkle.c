/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/merkle.h>

#include "sha256.h"

static size_t bpak_merkle_offset(struct bpak_merkle_context *ctx, int level)
{
    size_t result = 0;

    for (int i = ctx->no_of_levels; i > level; i--)
    {
        result += bpak_merkle_compute_size(ctx->fs_size, i, true);
    }

    return result;
}

static int bpak_merkle_next_level(struct bpak_merkle_context *ctx)
{
    if (ctx->current.level == ctx->no_of_levels)
        return -BPAK_FAILED;

    ctx->current.byte_counter = 0;

    memcpy(&ctx->previous, &ctx->current, sizeof(struct bpak_merkle_level));

    ctx->level++;
    ctx->current.level++;
    ctx->current.size = \
            bpak_merkle_compute_size(ctx->fs_size, ctx->current.level, false);
    ctx->current.padded_size = ctx->current.size +
                (MERKLE_BLOCK_SZ - (ctx->current.size % MERKLE_BLOCK_SZ));
    ctx->current.byte_counter = 0;
    ctx->current.offset = bpak_merkle_offset(ctx, ctx->current.level);
    return BPAK_OK;
}

size_t bpak_merkle_compute_size(size_t input_data_size, int level, bool pad)
{
    size_t tmp = input_data_size;
    size_t s = 0;
    size_t last_level = 0;
    int c = 0;

    if (input_data_size <= MERKLE_BLOCK_SZ && level < 1)
        return MERKLE_BLOCK_SZ;

    if ((tmp % MERKLE_BLOCK_SZ != 0) && pad)
        tmp += (MERKLE_BLOCK_SZ - (tmp % MERKLE_BLOCK_SZ));

    while ((tmp != MERKLE_BLOCK_SZ) && (c < MERKLE_MAX_LEVELS))
    {
        last_level = (tmp / MERKLE_BLOCK_SZ) * 32;

        if ((last_level % MERKLE_BLOCK_SZ != 0) && pad)
            last_level += (MERKLE_BLOCK_SZ - (last_level % MERKLE_BLOCK_SZ));

        s += last_level;

        if (c == level)
            return last_level;

        tmp = last_level;

        c++;
    }

    if (level > 0)
        return 0;

    return s;
}


int bpak_merkle_init(struct bpak_merkle_context *ctx,
                        size_t filesystem_size,
                        bpak_merkle_hash_t salt,
                        bpak_merkle_io_t wr,
                        bpak_merkle_io_t rd,
                        void *priv)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->wr = wr;
    ctx->rd = rd;
    ctx->fs_size = filesystem_size;
    ctx->current.level = -1;
    ctx->level = -1;
    ctx->priv = priv;

    memcpy(ctx->salt, salt, sizeof(bpak_merkle_hash_t));

    /* Compute size requirement for tree and amount of hash tree levels */
    while (ctx->no_of_levels < MERKLE_MAX_LEVELS)
    {
        size_t level_sz = bpak_merkle_compute_size(ctx->fs_size,
                                                    ctx->no_of_levels,
                                                    true);
        if (level_sz)
        {
            ctx->no_of_levels++;
            ctx->hash_tree_size += level_sz;

            if (level_sz % MERKLE_BLOCK_SZ != 0)
            {
                ctx->hash_tree_size +=
                    (MERKLE_BLOCK_SZ - (level_sz % MERKLE_BLOCK_SZ));
            }
        }
        else
        {
            break;
        }
    }

    return bpak_merkle_next_level(ctx);
}

size_t bpak_merkle_get_size(struct bpak_merkle_context *ctx)
{
    return ctx->hash_tree_size;
}


int bpak_merkle_process(struct bpak_merkle_context *ctx,
                            uint8_t *input, uint16_t sz)
{
    int rc = BPAK_OK;
    mbedtls_sha256_context hash;
    uint16_t chunk_sz = 0;
    uint8_t hash_tmp[32];
    uint64_t pos;
    int16_t pad = 0;

    memset(ctx->buffer, 0, MERKLE_BLOCK_SZ);

    if (ctx->current.level == 0)
    {
        chunk_sz = sz;
        memcpy(ctx->buffer, input, sz);
    }
    else
    {
        uint64_t bytes_r = ctx->previous.size - ctx->previous.byte_counter;
        chunk_sz = BPAK_MIN(bytes_r, MERKLE_BLOCK_SZ);

        pos = ctx->previous.offset + ctx->previous.byte_counter;

        rc = ctx->rd(ctx, pos, ctx->buffer, chunk_sz, ctx->priv);

        if (rc != BPAK_OK)
            return rc;

        ctx->previous.byte_counter += chunk_sz;
    }

    mbedtls_sha256_init(&hash);
    mbedtls_sha256_starts_ret(&hash, 0);
    mbedtls_sha256_update_ret(&hash, ctx->salt, 32);
    mbedtls_sha256_update_ret(&hash, ctx->buffer, MERKLE_BLOCK_SZ);
    mbedtls_sha256_finish_ret(&hash, hash_tmp);

    pos = ctx->current.offset + ctx->current.byte_counter;
    ctx->wr(ctx, pos, hash_tmp, 32, ctx->priv);
    ctx->current.byte_counter += 32;

    if (ctx->status)
        ctx->status(ctx);

    if (ctx->current.byte_counter == ctx->current.size)
    {
        bool padding_needed = \
                     ((ctx->current.byte_counter % MERKLE_BLOCK_SZ) != 0);
        if (padding_needed)
        {
            memset(ctx->buffer, 0, sizeof(ctx->buffer));
            pos = ctx->current.offset + ctx->current.byte_counter;
            pad = MERKLE_BLOCK_SZ - (ctx->current.byte_counter % MERKLE_BLOCK_SZ);
            ctx->wr(ctx, pos, ctx->buffer, pad, ctx->priv);
            ctx->current.byte_counter += pad;
        }

        bpak_merkle_next_level(ctx);

        if (padding_needed)
            ctx->current.size += 32;
    }

    return rc;
}

int bpak_merkle_set_status_cb(struct bpak_merkle_context *ctx,
                              bpak_merkle_status_t sts)
{
    ctx->status = sts;
    return BPAK_OK;
}

bool bpak_merkle_done(struct bpak_merkle_context *ctx)
{
    return (ctx->current.level == ctx->no_of_levels);
}

int bpak_merkle_out(struct bpak_merkle_context *ctx,
                        bpak_merkle_hash_t roothash)
{
    mbedtls_sha256_context hash;
    uint64_t pos = ctx->current.offset;

    ctx->rd(ctx, pos, ctx->buffer, MERKLE_BLOCK_SZ, ctx->priv);

    mbedtls_sha256_init(&hash);
    mbedtls_sha256_starts_ret(&hash, 0);
    mbedtls_sha256_update_ret(&hash, ctx->salt, 32);
    mbedtls_sha256_update_ret(&hash, ctx->buffer, MERKLE_BLOCK_SZ);
    mbedtls_sha256_finish_ret(&hash, roothash);

    if (bpak_merkle_done(ctx))
        return BPAK_OK;
    else
        return -BPAK_FAILED;
}

