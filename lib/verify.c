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
#include <bpak/id.h>
#include <bpak/crc.h>
#include <bpak/verify.h>
#include <bpak/merkle.h>
#include <bpak/crypto.h>

BPAK_EXPORT int bpak_verify_compute_header_hash(struct bpak_header *header,
                                    uint8_t *output,
                                    size_t *size)
{
    uint8_t signature[BPAK_SIGNATURE_MAX_BYTES];
    uint16_t signature_sz;
    int rc;
    struct bpak_hash_context hash_ctx;

    /* Compute header hash */
    rc = bpak_hash_init(&hash_ctx, header->hash_kind);

    if (rc != BPAK_OK)
        return rc;

    memcpy(signature, header->signature, sizeof(signature));
    signature_sz = header->signature_sz;

    memset(header->signature, 0, sizeof(header->signature));
    header->signature_sz = 0;


    rc = bpak_hash_update(&hash_ctx, (uint8_t *) header,
                                     sizeof(*header));

    if (rc != BPAK_OK)
        goto err_free_hash_ctx_out;

    rc = bpak_hash_final(&hash_ctx, output, *size, size);

    if (rc != BPAK_OK)
        goto err_free_hash_ctx_out;

err_free_hash_ctx_out:
    bpak_hash_free(&hash_ctx);
    memcpy(header->signature, signature, sizeof(signature));
    header->signature_sz = signature_sz;
    return BPAK_OK;
}

BPAK_EXPORT int bpak_verify_compute_payload_hash(struct bpak_header *header,
                                    bpak_io_t read_payload,
                                    off_t data_offset,
                                    void *user,
                                    uint8_t *output,
                                    size_t *size)
{
    off_t current_offset = data_offset;
    unsigned char chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    int rc;
    struct bpak_hash_context hash_ctx;

    rc = bpak_hash_init(&hash_ctx, header->hash_kind);

    if (rc != BPAK_OK)
        return rc;

    bpak_foreach_part(header, p) {
        size_t bytes_to_read = bpak_part_size(p);
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH) {
            current_offset += bpak_part_size(p);
            continue;
        }

        do {
            chunk = (bytes_to_read > sizeof(chunk_buffer))?
                        sizeof(chunk_buffer):bytes_to_read;

            if (read_payload(current_offset, chunk_buffer, chunk, user) != (ssize_t) chunk) {
                rc = -BPAK_READ_ERROR;
                goto err_free_hash_ctx_out;
            }

            rc = bpak_hash_update(&hash_ctx, chunk_buffer, chunk);

            if (rc != BPAK_OK)
                goto err_free_hash_ctx_out;

            bytes_to_read -= chunk;
            current_offset += chunk;
        } while (bytes_to_read);
    }

    rc = bpak_hash_final(&hash_ctx, output, *size, size);

    if (rc != BPAK_OK)
        goto err_free_hash_ctx_out;

err_free_hash_ctx_out:
    bpak_hash_free(&hash_ctx);
    return rc;
}

#if BPAK_CONFIG_MERKLE == 1
struct merkle_verify_private
{
    void *user;
    bpak_io_t read_payload;
};

static ssize_t merkle_verify_wr(off_t offset, uint8_t *buf, size_t size,
                                void *user)
{
    uint8_t chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    ssize_t chunk_length;
    size_t bytes_to_process = size;
    struct merkle_verify_private *priv = (struct merkle_verify_private *) user;
    off_t current_offset = 0;

    while (bytes_to_process) {
        chunk_length = BPAK_MIN(bytes_to_process, sizeof(chunk_buffer));

        ssize_t bytes_read = priv->read_payload(current_offset + offset,
                                     chunk_buffer, chunk_length, priv->user);

        if (bytes_read < 0)
            return bytes_read;
        if (bytes_read != chunk_length)
            return -BPAK_READ_ERROR;

        if (memcmp(&buf[current_offset], chunk_buffer, chunk_length) != 0) {
            return -BPAK_VERIFY_FAIL;
        }
        bytes_to_process -= chunk_length;
        current_offset += chunk_length;
    }
    return size;
}

static ssize_t merkle_verify_rd(off_t offset, uint8_t *buf, size_t size,
                                void *user)
{
    struct merkle_verify_private *priv = (struct merkle_verify_private *) user;
    return priv->read_payload(offset, buf, size, priv->user);
}

BPAK_EXPORT int bpak_verify_merkle_tree(bpak_io_t read_payload,
                            off_t data_offset,
                            size_t data_length,
                            off_t tree_offset,
                            bpak_merkle_hash_t expected_root_hash,
                            bpak_merkle_hash_t salt,
                            void *user)
{
    int rc;
    struct bpak_merkle_context ctx;
    uint8_t chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    struct merkle_verify_private merkle_verify_private;

    memset(&merkle_verify_private, 0, sizeof(merkle_verify_private));
    merkle_verify_private.read_payload = read_payload;
    merkle_verify_private.user = user;

    rc = bpak_merkle_init(&ctx,
                          data_length,
                          salt,
                          32,
                          merkle_verify_wr,
                          merkle_verify_rd,
                          tree_offset,
                          false,
                          &merkle_verify_private);

    if (rc != BPAK_OK) {
        return rc;
    }

    size_t bytes_to_process = data_length;
    off_t current_offset = data_offset;

    while (bytes_to_process > 0) {
        ssize_t chunk_length = BPAK_MIN(bytes_to_process, sizeof(chunk_buffer));

        ssize_t bytes_read = read_payload(current_offset, chunk_buffer,
                                          chunk_length, user);

        if (bytes_read < 0)
            return bytes_read;
        if (bytes_read != chunk_length)
            return -BPAK_READ_ERROR;

        rc = bpak_merkle_write_chunk(&ctx, chunk_buffer, chunk_length);

        if (rc != BPAK_OK) {
            return rc;
        }

        bytes_to_process -= chunk_length;
        current_offset += chunk_length;
    }

    bpak_merkle_hash_t calculated_root_hash;

    rc = bpak_merkle_finish(&ctx, calculated_root_hash);

    if (rc != BPAK_OK)
        return rc;

    if (memcmp(calculated_root_hash, expected_root_hash,
            sizeof(*expected_root_hash)) != 0) {
        return -BPAK_BAD_ROOT_HASH;
    }

    return BPAK_OK;
}
#endif  // BPAK_CONFIG_MERKLE

BPAK_EXPORT int bpak_verify_payload(struct bpak_header *header,
                        bpak_io_t read_payload,
                        off_t data_offset,
                        void *user)
{
    int rc;
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t hash_length = sizeof(hash);

    /* Compute and compare payload hash */
    rc = bpak_verify_compute_payload_hash(header,
                                          read_payload,
                                          data_offset,
                                          user,
                                          hash,
                                          &hash_length);

    if (rc != BPAK_OK)
        return rc;

    if (memcmp(hash, header->payload_hash, hash_length) != 0) {
        return -BPAK_BAD_PAYLOAD_HASH;
    }

#if BPAK_CONFIG_MERKLE == 1
    const char *hash_tree_suffix = "-hash-tree";
    uint8_t *part_merkle_root_hash;
    uint8_t *part_merkle_salt;

    /* Compute and compare merkle hash trees and root hashes */
    bpak_foreach_part(header, p) {
        if (!p->id)
            continue;

        /* Test part to see if it has a hash tree */
        rc = bpak_get_meta_with_ref(header, BPAK_ID_MERKLE_ROOT_HASH,
                                p->id, (void **) &part_merkle_root_hash, NULL);

        if (rc != BPAK_OK) {
            /* This part does not have a merkle tree, skip to next part */
            continue;
        }

        /* There should also be a salt meta data for this part */
        rc = bpak_get_meta_with_ref(header, BPAK_ID_MERKLE_SALT,
                                    p->id, (void **) &part_merkle_salt, NULL);

        if (rc != BPAK_OK)
            return -BPAK_MISSING_META_DATA;

        /* Compute the part id for the merkle tree, this is always an
         *  extension of the data part id, suffixed with '-hash-tree'
         */
        uint32_t merkle_tree_part_id = bpak_crc32(p->id, (uint8_t *) hash_tree_suffix,
                                                 strlen(hash_tree_suffix));

        struct bpak_part_header *merkle_tree_part = NULL;

        /* Get the hash tree meta data header */
        rc = bpak_get_part(header, merkle_tree_part_id, &merkle_tree_part);

        if (rc != BPAK_OK) {
            return rc;
        }

        /* Compute part data and tree offsets relative input 'data_offset' */
        off_t part_data_offset = bpak_part_offset(header, p) -
                                    sizeof(struct bpak_header) + data_offset;
        off_t part_tree_offset = bpak_part_offset(header, merkle_tree_part) -
                                    sizeof(struct bpak_header) + data_offset;

        /* Verify this data/merkle tree and compare the root hash */
        rc = bpak_verify_merkle_tree(read_payload,
                                     part_data_offset,
                                     bpak_part_size(p),
                                     part_tree_offset,
                                     part_merkle_root_hash,
                                     part_merkle_salt,
                                     user);

        if (rc != BPAK_OK) {
            return rc;
        }
    }
#endif  // BPAK_CONFIG_MERKLE

    return BPAK_OK;
}
