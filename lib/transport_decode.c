/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <inttypes.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/transport.h>
#include <bpak/bspatch.h>
#include <bpak/merkle.h>
#include <bpak/id.h>
#include <bpak/utils.h>

#include "internal.h"

/* True if [offset, offset + length) is within [start, start + size) */
static bool range_within(off_t offset, size_t length, off_t start,
                         uint64_t size)
{
    if (offset < start)
        return false;

    uint64_t relative = (uint64_t)(offset - start);

    return relative <= size && length <= size - relative;
}

/* Patches are not authenticated, the output of bspatch must stay within the
 * part and the origin reads within the origin part */
static ssize_t bspatch_write_output(off_t offset, uint8_t *buffer,
                                    size_t length, void *user)
{
    struct bpak_transport_decode *ctx = (struct bpak_transport_decode *)user;

    if (!range_within(offset,
                      length,
                      ctx->decoders.bspatch.output_offset,
                      bpak_part_decoded_size(ctx->part))) {
        bpak_printf(0, "Error: Patch writes outside of the part\n");
        return -BPAK_PATCH_WRITE_ERROR;
    }

    return ctx->write_output(offset, buffer, length, ctx->user);
}

static ssize_t bspatch_read_origin(off_t offset, uint8_t *buffer, size_t length,
                                   void *user)
{
    struct bpak_transport_decode *ctx = (struct bpak_transport_decode *)user;
    struct bpak_part_header *origin_part = NULL;

    if (bpak_get_part(ctx->origin_header, ctx->part->id, &origin_part) !=
            BPAK_OK ||
        !range_within(offset,
                      length,
                      ctx->decoders.bspatch.origin_offset,
                      bpak_part_size(origin_part))) {
        bpak_printf(0, "Error: Patch reads outside of the origin part\n");
        return -BPAK_PATCH_READ_ORIGIN_ERROR;
    }

    return ctx->read_origin(offset, buffer, length, ctx->user);
}

#if BPAK_CONFIG_MERKLE == 1
static ssize_t merkle_generate(struct bpak_transport_decode *ctx)
{
    int rc;
    struct bpak_part_header *fs_part;
    uint8_t chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    uint32_t fs_id = 0;
    uint8_t *salt = NULL;
    uint8_t *expected_root_hash = NULL;
    size_t bytes_to_process;
    size_t chunk_length;

    /* The part id currently begin processed is for the hash tree,
     *  Locate the filesystem that should be used */
    fs_id = bpak_hash_tree_id_to_part_id(ctx->patch_header, ctx->part->id);

    if (!fs_id) {
        bpak_printf(0, "Error: could not find hash tree\n");
        return -BPAK_MISSING_META_DATA;
    }

    /* Load the salt that should be used */
    rc = bpak_get_meta_value(ctx->patch_header,
                             BPAK_ID_MERKLE_SALT,
                             fs_id,
                             BPAK_MERKLE_HASH_BYTES,
                             BPAK_MERKLE_HASH_BYTES,
                             &salt);

    if (rc != BPAK_OK) {
        bpak_printf(0,
                    "Error: Could not load merkle salt for part 0x%x\n",
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

    /* The tree must fit the part before it is written */
    ssize_t tree_size = bpak_merkle_compute_size(bpak_part_size(fs_part));

    if (tree_size < 0)
        return tree_size;

    if ((uint64_t)tree_size != bpak_part_decoded_size(ctx->part)) {
        bpak_printf(0, "Error: The hash tree does not fit the part\n");
        return -BPAK_SIZE_ERROR;
    }

    off_t output_offset =
        bpak_part_data_offset(ctx->patch_header, ctx->part, ctx->output_offset);

    bpak_printf(2, "Merkle tree at offset: %lld\n", (long long)output_offset);

    rc = bpak_merkle_init(&ctx->decoders.merkle,
                          bpak_part_size(fs_part),
                          salt,
                          BPAK_MERKLE_HASH_BYTES,
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
    off_t data_offset =
        bpak_part_data_offset(ctx->patch_header, fs_part, ctx->output_offset);

    bytes_to_process = bpak_part_size(fs_part);
    while (bytes_to_process) {
        size_t bytes_to_read = BPAK_MIN(bytes_to_process, sizeof(chunk_buffer));
        chunk_length = ctx->read_output(data_offset,
                                        chunk_buffer,
                                        bytes_to_read,
                                        ctx->user);

        if (chunk_length != bytes_to_read) {
            bpak_printf(0,
                        "Error: Wanted to read %zu at offset %lld but got "
                        "%zd\n",
                        bytes_to_read,
                        (long long)data_offset,
                        (ssize_t)chunk_length);
            return -BPAK_READ_ERROR;
        }

        rc = bpak_merkle_write_chunk(&ctx->decoders.merkle,
                                     chunk_buffer,
                                     chunk_length);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
            return rc;
        }

        data_offset += chunk_length;
        bytes_to_process -= chunk_length;
    }

    bpak_merkle_hash_t roothash;
    rc = bpak_merkle_finish(&ctx->decoders.merkle, roothash);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
        return rc;
    }

    /* The signed root hash, the header is verified after decoding but a
     * mismatch is found here already */
    rc = bpak_get_meta_value(ctx->patch_header,
                             BPAK_ID_MERKLE_ROOT_HASH,
                             fs_id,
                             BPAK_MERKLE_HASH_BYTES,
                             BPAK_MERKLE_HASH_BYTES,
                             &expected_root_hash);

    if (rc == -BPAK_NOT_FOUND)
        return -BPAK_MISSING_META_DATA;
    if (rc != BPAK_OK)
        return rc;

    if (memcmp(roothash, expected_root_hash, BPAK_MERKLE_HASH_BYTES) != 0) {
        bpak_printf(0, "Error: The merkle root hash does not match\n");
        return -BPAK_BAD_ROOT_HASH;
    }

    return bpak_merkle_get_size(&ctx->decoders.merkle);
}

#endif // BPAK_CONFIG_MERKLE

BPAK_EXPORT int bpak_transport_decode_init(
    struct bpak_transport_decode *ctx, uint8_t *buffer, size_t buffer_length,
    struct bpak_header *patch_header, bpak_io_t write_output,
    bpak_io_t read_output, off_t output_offset, bpak_io_t write_output_header,
    void *user)
{
    int rc;

    memset(ctx, 0, sizeof(*ctx));

    /* The header of a transport encoded package can not be verified before
     * it is decoded */
    rc = bpak_valid_header(patch_header);

    if (rc != BPAK_OK)
        return rc;

    ctx->buffer = buffer;
    ctx->buffer_length = buffer_length;
    ctx->patch_header = patch_header;
    ctx->write_output = write_output;
    ctx->read_output = read_output;
    ctx->write_output_header = write_output_header;
    ctx->output_offset = output_offset;
    ctx->user = user;

    return BPAK_OK;
}

BPAK_EXPORT int
bpak_transport_decode_set_origin(struct bpak_transport_decode *ctx,
                                 struct bpak_header *origin_header,
                                 bpak_io_t read_origin, off_t origin_offset)
{
    int rc;

    rc = bpak_valid_header(origin_header);

    if (rc != BPAK_OK)
        return rc;

    ctx->origin_header = origin_header;
    ctx->read_origin = read_origin;
    ctx->origin_offset = origin_offset;

    /* Origin and input package should have the same package-uuid */
    return bpak_same_package_uuid(origin_header, ctx->patch_header);
}

/* Write the header, the decoder clears the transport flags of the parts that
 * it decoded */
static int write_output_header(struct bpak_transport_decode *ctx)
{
    ssize_t bytes_written =
        ctx->write_output_header(0,
                                 (uint8_t *)ctx->patch_header,
                                 sizeof(struct bpak_header),
                                 ctx->user);

    if (bytes_written < 0)
        return bytes_written;
    if (bytes_written != sizeof(struct bpak_header))
        return -BPAK_WRITE_ERROR;

    return BPAK_OK;
}

/* Free the state of the decoder of the current part. bspatch can be freed
 * more than once. */
static void decoder_free(struct bpak_transport_decode *ctx)
{
    switch (ctx->decoder_id) {
    case BPAK_ID_BSPATCH_NO_COMP:
    case BPAK_ID_BSPATCH_LZMA:
    case BPAK_ID_BSPATCH:
        bpak_bspatch_free(&ctx->decoders.bspatch);
        break;
    default:
        break;
    }

    ctx->decoder_id = 0;
}

BPAK_EXPORT int bpak_transport_decode_start(struct bpak_transport_decode *ctx,
                                            struct bpak_part_header *part)
{
    int rc;
    struct bpak_meta_header *meta = NULL;

    rc = write_output_header(ctx);

    if (rc != BPAK_OK)
        return rc;

    /* A previous part that was not finished */
    decoder_free(ctx);

    ctx->part = part;

    /* Check if there is any transport meta data for this part in the header */
    if (part->flags & BPAK_FLAG_TRANSPORT) {
        if (bpak_get_meta(ctx->patch_header,
                          BPAK_ID_BPAK_TRANSPORT,
                          part->id,
                          &meta) == BPAK_OK) {
            ctx->decoder_id =
                bpak_get_meta_ptr(ctx->patch_header, meta,
                                  struct bpak_transport_meta)->alg_id_decode;
        }
    }

    switch (ctx->decoder_id) {
    case BPAK_ID_BSPATCH: /* heatshrink decompressor*/
    case BPAK_ID_BSPATCH_NO_COMP:
    case BPAK_ID_BSPATCH_LZMA: {
        if (ctx->read_origin == NULL) {
            /* bspach requires the origin stream */
            return -BPAK_PATCH_READ_ORIGIN_ERROR;
        }

        struct bpak_part_header *origin_part = NULL;

        rc = bpak_get_part(ctx->origin_header, part->id, &origin_part);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: The origin has no part %08x\n", part->id);
            return rc;
        }

        size_t patch_input_length = bpak_part_size(part);
        bpak_printf(2, "Patch input length: %zu\n", patch_input_length);

        enum bpak_compression compression = BPAK_COMPRESSION_NONE;

        if (ctx->decoder_id == BPAK_ID_BSPATCH)
            compression = BPAK_COMPRESSION_HS;
        else if (ctx->decoder_id == BPAK_ID_BSPATCH_LZMA)
            compression = BPAK_COMPRESSION_LZMA;

        /* Compute output and origin offsets */
        off_t output_offset =
            bpak_part_data_offset(ctx->patch_header, part, ctx->output_offset);
        off_t origin_offset =
            bpak_part_data_offset(ctx->origin_header, part, ctx->origin_offset);

        rc = bpak_bspatch_init(&ctx->decoders.bspatch,
                               ctx->buffer,
                               ctx->buffer_length,
                               patch_input_length,
                               bspatch_read_origin,
                               origin_offset,
                               bspatch_write_output,
                               output_offset,
                               compression,
                               ctx);

    } break;
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

BPAK_EXPORT int
bpak_transport_decode_write_chunk(struct bpak_transport_decode *ctx,
                                  uint8_t *buffer, size_t length)
{
    int rc;

    switch (ctx->decoder_id) {
    case BPAK_ID_BSPATCH_NO_COMP:
    case BPAK_ID_BSPATCH_LZMA:
    case BPAK_ID_BSPATCH: /* id("bspatch") heatshrink decompressor*/
    {
        rc = bpak_bspatch_write(&ctx->decoders.bspatch, buffer, length);
    } break;
    case 0: /* Copy data */
    {
        uint64_t part_size = bpak_part_decoded_size(ctx->part);

        if ((uint64_t)ctx->copy_offset > part_size ||
            length > part_size - ctx->copy_offset) {
            bpak_printf(0, "Error: Too much data for the part\n");
            return -BPAK_SIZE_ERROR;
        }

        off_t write_offset = bpak_part_data_offset(ctx->patch_header,
                                                   ctx->part,
                                                   ctx->output_offset) +
                             ctx->copy_offset;

        ssize_t bytes_written =
            ctx->write_output(write_offset, buffer, length, ctx->user);
        if (bytes_written < 0)
            return bytes_written;
        if (bytes_written != (ssize_t)length)
            return -BPAK_WRITE_ERROR;

        ctx->copy_offset += bytes_written;
        rc = 0;
    } break;
    default:
        return -BPAK_NOT_SUPPORTED;
    }

    return rc;
}

BPAK_EXPORT int bpak_transport_decode_finish(struct bpak_transport_decode *ctx)
{
    ssize_t output_length = 0;

    switch (ctx->decoder_id) {
    case BPAK_ID_BSPATCH_NO_COMP:
    case BPAK_ID_BSPATCH_LZMA:
    case BPAK_ID_BSPATCH: /* id("bspatch") heatshrink decompressor*/
    {
        output_length = bpak_bspatch_final(&ctx->decoders.bspatch);
        bpak_bspatch_free(&ctx->decoders.bspatch);
    } break;
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
    if (output_length != (ssize_t)bpak_part_decoded_size(ctx->part)) {
        bpak_printf(0,
                    "Error: Decoded part size does not match the expected size "
                    "%" PRIu64 " != %zd\n",
                    bpak_part_decoded_size(ctx->part),
                    output_length);
        return -BPAK_SIZE_ERROR;
    }

    /* Update part header to indicate that the part has been decoded */
    ctx->part->flags &= ~BPAK_FLAG_TRANSPORT;
    ctx->part->transport_size = 0;

    return write_output_header(ctx);
}

BPAK_EXPORT void bpak_transport_decode_free(struct bpak_transport_decode *ctx)
{
    /* Decoding stopped in the middle of a part */
    decoder_free(ctx);
}
