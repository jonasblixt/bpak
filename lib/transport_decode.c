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
#include <bpak/crc.h>
#include <bpak/transport.h>
#include <bpak/bspatch.h>
#include <bpak/merkle.h>
#include <bpak/id.h>

#if BPAK_CONFIG_MERKLE == 1
static ssize_t merkle_generate(struct bpak_transport_decode *ctx)
{
    int rc;
    struct bpak_merkle_context merkle;
    struct bpak_part_header *fs_part;
    uint8_t chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    uint32_t fs_id = 0;
    uint8_t *salt = NULL;
    size_t bytes_to_process;
    size_t chunk_length;

    /* The part id currently begin processed is for the hash tree,
     *  Locate the filesystem that should be used */
    bpak_foreach_part(ctx->patch_header, part) {
        if (bpak_crc32(part->id, (uint8_t *) "-hash-tree", 10) == ctx->part->id) {
            fs_id = part->id;
            break;
        }
    }

    if (!fs_id) {
        bpak_printf(0, "Error: could not find hash tree\n");
        return -BPAK_MISSING_META_DATA;
    }

    /* Load the salt that should be used */
    rc = bpak_get_meta_with_ref(ctx->patch_header, BPAK_ID_MERKLE_SALT, fs_id,
                                (void **) &salt, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not load merkle salt for part 0x%x\n",
                            fs_id);
        return rc;
    }

    /* Get filesystem header */
    fs_part = NULL;
    rc = bpak_get_part(ctx->patch_header, fs_id, &fs_part);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not read filesystem header\n");
        return rc;
    }

    off_t output_offset = bpak_part_offset(ctx->patch_header, ctx->part) -
                            sizeof(struct bpak_header) +
                            ctx->output_offset;

    bpak_printf(0, "Merkle tree at offset: %i\n", output_offset);

    rc = bpak_merkle_init(&merkle,
                          bpak_part_size(fs_part),
                          salt,
                          32,
                          ctx->write_output,
                          ctx->read_output,
                          output_offset,
                          true,
                          ctx->user);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not init bpak merkle\n");
        return rc;
    }

    /* Source data is alwas in the part before the hash tree
     * And the user read/write calls are expected to offset io calls
     * to the hashtree, therefore the data should be at an offset
     * of -bpak_part_size(fs_part) */
    off_t data_offset = bpak_part_offset(ctx->patch_header, fs_part) -
                            sizeof(struct bpak_header) + ctx->output_offset;

    bytes_to_process = bpak_part_size(fs_part);
    while (bytes_to_process) {
        size_t bytes_to_read = BPAK_MIN(bytes_to_process, sizeof(chunk_buffer));
        chunk_length = ctx->read_output(data_offset,
                                        chunk_buffer,
                                        bytes_to_read,
                                        ctx->user);

        if (chunk_length != bytes_to_read) {
            bpak_printf(0, "Error: Wanted to read %zu at offset %i but got %i\n",
                            bytes_to_read, ctx->output_offset + data_offset,
                            chunk_length);
            return -BPAK_READ_ERROR;
        }

        rc = bpak_merkle_write_chunk(&merkle, chunk_buffer, chunk_length);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
            return rc;
        }

        data_offset += chunk_length;
        bytes_to_process -= chunk_length;
    }

    bpak_merkle_hash_t roothash;
    rc = bpak_merkle_finish(&merkle, roothash);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
        return rc;
    }

    // TODO: Check roothash?
    return bpak_merkle_get_size(&merkle);
}

#endif  // BPAK_CONFIG_MERKLE

int bpak_transport_decode_init(struct bpak_transport_decode *ctx,
                               size_t buffer_length,
                               struct bpak_header *patch_header,
                               bpak_io_t write_output,
                               bpak_io_t read_output,
                               off_t output_offset,
                               bpak_io_t write_output_header,
                               void *user)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->buffer_length = buffer_length;
    ctx->patch_header = patch_header;
    ctx->write_output = write_output;
    ctx->read_output = read_output;
    ctx->write_output_header = write_output_header;
    ctx->output_offset = output_offset;
    ctx->user = user;

    return BPAK_OK;
}

int bpak_transport_decode_set_origin(struct bpak_transport_decode *ctx,
                                     struct bpak_header *origin_header,
                                     bpak_io_t read_origin,
                                     off_t origin_offset)
{
    int rc;
    uint8_t *origin_package_uuid;
    uint8_t *patch_package_uuid;

    ctx->origin_header = origin_header;
    ctx->read_origin = read_origin;
    ctx->origin_offset = origin_offset;

    /* Origin and input package should have the same package-uuid */
    rc = bpak_get_meta(origin_header, BPAK_ID_BPAK_PACKAGE,
                                (void **) &origin_package_uuid, NULL);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_get_meta(ctx->patch_header, BPAK_ID_BPAK_PACKAGE,
                                (void **) &patch_package_uuid, NULL);

    if (rc != BPAK_OK)
        return rc;

    if (memcmp(origin_package_uuid, patch_package_uuid, 16) != 0)
        return -BPAK_PACKAGE_UUID_MISMATCH;

    return BPAK_OK;
}

int bpak_transport_decode_start(struct bpak_transport_decode *ctx,
                                struct bpak_part_header *part)
{
    int rc;
    struct bpak_transport_meta *tm = NULL;
    ssize_t bytes_written;

    bytes_written = ctx->write_output_header(0, (uint8_t *) ctx->patch_header,
                                             sizeof(struct bpak_header),
                                             ctx->user);

    if (bytes_written < 0)
        return bytes_written;
    if (bytes_written != sizeof(struct bpak_header))
        return -BPAK_WRITE_ERROR;

    ctx->part = part;
    ctx->decoder_id = 0;

    /* Check if there is any transport meta data for this part in the header */
    if (part->flags & BPAK_FLAG_TRANSPORT) {
        if (bpak_get_meta_with_ref(ctx->patch_header,
                                   BPAK_ID_BPAK_TRANSPORT,
                                   part->id,
                                   (void **) &tm, NULL) == BPAK_OK) {
            ctx->decoder_id = tm->alg_id_decode;
        }
    }

    switch (ctx->decoder_id) {
        case BPAK_ID_BSPATCH: /* heatshrink decompressor*/
        case BPAK_ID_BSPATCH_NO_COMP:
        case BPAK_ID_BSPATCH_LZMA:
        {
            if (ctx->read_origin == NULL) {
                /* bspach requires the origin stream */
                return -BPAK_PATCH_READ_ORIGIN_ERROR;
            }

            size_t patch_input_length = bpak_part_size(part);
            bpak_printf(2, "Patch input length: %zu\n", patch_input_length);

            enum bpak_compression compression;

            if (ctx->decoder_id == BPAK_ID_BSPATCH)
                compression = BPAK_COMPRESSION_HS;
            else if (ctx->decoder_id == BPAK_ID_BSPATCH_NO_COMP)
                compression = BPAK_COMPRESSION_NONE;
            else if (ctx->decoder_id == BPAK_ID_BSPATCH_LZMA)
                compression = BPAK_COMPRESSION_LZMA;
            else
                return -BPAK_UNSUPPORTED_COMPRESSION;

            ctx->decoder_priv = bpak_calloc(sizeof(struct bpak_bspatch_context), 1);

            struct bpak_bspatch_context *bspatch = \
                    (struct bpak_bspatch_context *) ctx->decoder_priv;

            /* Compute output and origin offsets */
            off_t output_offset = bpak_part_offset(ctx->patch_header, part) -
                                    sizeof(struct bpak_header) +
                                    ctx->output_offset;

            off_t origin_offset = bpak_part_offset(ctx->origin_header, part) -
                                    sizeof(struct bpak_header) +
                                    ctx->origin_offset;

            rc = bpak_bspatch_init(bspatch,
                                     ctx->buffer_length,
                                     patch_input_length,
                                     ctx->read_origin,
                                     origin_offset,
                                     ctx->write_output,
                                     output_offset,
                                     compression,
                                     ctx->user);

            if (rc != BPAK_OK) {
                bpak_free(bspatch);
            }
        }
        break;
#if BPAK_CONFIG_MERKLE == 1
        case BPAK_ID_MERKLE_GENERATE:
            /* Merkle trees are generated from output data
             *  of a previous patch step, this is done in the final call */
            rc = BPAK_OK;
        break;
#endif
        case 0: /* Copy data */
            ctx->copy_offset = 0;
            rc = BPAK_OK;
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    return rc;
}


int bpak_transport_decode_write_chunk(struct bpak_transport_decode *ctx,
                                      uint8_t *buffer, size_t length)
{
    int rc;

    switch (ctx->decoder_id) {
        case BPAK_ID_BSPATCH_NO_COMP:
        case BPAK_ID_BSPATCH_LZMA:
        case BPAK_ID_BSPATCH: /* id("bspatch") heatshrink decompressor*/
        {
            struct bpak_bspatch_context *bspatch = \
                    (struct bpak_bspatch_context *) ctx->decoder_priv;

            rc = bpak_bspatch_write(bspatch, buffer, length);

            if (rc != BPAK_OK)
                bpak_free(bspatch);
        }
        break;
        case 0: /* Copy data */
        {
            off_t write_offset = bpak_part_offset(ctx->patch_header, ctx->part) -
                                    sizeof(struct bpak_header) +
                                    ctx->output_offset +
                                    ctx->copy_offset;

            ssize_t bytes_written = ctx->write_output(write_offset,
                                                      buffer,
                                                      length,
                                                      ctx->user);
            if (bytes_written < 0)
                return bytes_written;
            if (bytes_written != (ssize_t) length)
                return -BPAK_WRITE_ERROR;

            ctx->copy_offset += bytes_written;
            rc = 0;
        }
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    return rc;
}

int bpak_transport_decode_finish(struct bpak_transport_decode *ctx)
{
    ssize_t bytes_written;
    ssize_t output_length = 0;

    switch (ctx->decoder_id) {
        case BPAK_ID_BSPATCH_NO_COMP:
        case BPAK_ID_BSPATCH_LZMA:
        case BPAK_ID_BSPATCH: /* id("bspatch") heatshrink decompressor*/
        {
            struct bpak_bspatch_context *bspatch = \
                    (struct bpak_bspatch_context *) ctx->decoder_priv;

            output_length = bpak_bspatch_final(bspatch);

            bpak_bspatch_free(bspatch);
            bpak_free(bspatch);
        }
        break;
#if BPAK_CONFIG_MERKLE == 1
        case BPAK_ID_MERKLE_GENERATE: /* id("merkle-generate") */
            output_length = merkle_generate(ctx);
        break;
#endif
        case 0: /* Copy data */
            output_length = bpak_part_size(ctx->part);
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    if (output_length < 0)
        return output_length;

    /* Check that the produced output length matches what the patch input
     * header says */
    if (output_length != (ssize_t) (ctx->part->size + ctx->part->pad_bytes)) {
        bpak_printf(0, "Error: Decoded part size does not match the expected size %zu != %zu\n",
                        (ctx->part->size + ctx->part->pad_bytes), output_length);
        return -BPAK_SIZE_ERROR;
    }

    /* Update part header to indicate that the part has been decoded */
    ctx->part->flags &= ~BPAK_FLAG_TRANSPORT;
    ctx->part->transport_size = 0;

    bytes_written = ctx->write_output_header(0, (uint8_t *) ctx->patch_header,
                                             sizeof(struct bpak_header),
                                             ctx->user);

    if (bytes_written < 0)
        return bytes_written;
    if (bytes_written != sizeof(struct bpak_header))
        return -BPAK_WRITE_ERROR;
    return BPAK_OK;
}

void bpak_transport_decode_free(struct bpak_transport_decode *ctx)
{
    /* Nothing to implement so far */
    (void) ctx;
}
