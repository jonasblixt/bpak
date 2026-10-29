/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/verify.h>
#include <bpak/keystore.h>

#include "internal.h"

BPAK_EXPORT int bpak_pkg_verify(struct bpak_package *pkg,
                                struct bpak_key *key)
{
    int rc;
    uint8_t hash_output[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash_output);
    bool header_verified = false;

    /* The signature size is not covered by the header hash */
    if (pkg->header.signature_sz > sizeof(pkg->header.signature))
        return -BPAK_SIZE_ERROR;

    rc = bpak_verify_compute_header_hash(&pkg->header, hash_output, &hash_size);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_crypto_verify(pkg->header.signature,
                            pkg->header.signature_sz,
                            hash_output,
                            hash_size,
                            pkg->header.hash_kind,
                            key,
                            &header_verified);

    if (rc != BPAK_OK)
        goto err_out;
    if (header_verified == false) {
        rc = -BPAK_VERIFY_FAIL;
        goto err_out;
    }

    rc = bpak_verify_payload(&pkg->header,
                             bpak_file_read,
                             sizeof(struct bpak_header),
                             pkg->fp);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: payload verification failed\n");
        goto err_out;
    }

err_out:
    return rc;
}

static int hash_chunk(void *priv, uint8_t *buffer, size_t length)
{
    return bpak_hash_update(priv, buffer, length);
}

BPAK_EXPORT int bpak_pkg_part_sha256(struct bpak_package *pkg,
                                     uint8_t *hash_buffer,
                                     size_t hash_buffer_length,
                                     uint32_t part_id)
{
    int rc;
    struct bpak_part_header *part;
    struct bpak_hash_context hash;
    off_t offset;

    rc = bpak_get_part(&pkg->header, part_id, &part);

    if (rc != BPAK_OK)
        return rc;

    offset = bpak_part_offset(&pkg->header, part);

    rc = bpak_hash_init(&hash, BPAK_HASH_SHA256);

    if (rc != BPAK_OK)
        return rc;

    if (fseeko(pkg->fp, offset, SEEK_SET) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_free_hash_ctx_out;
    }

    rc =
        bpak_file_feed(pkg->fp, bpak_part_size_wo_pad(part), hash_chunk, &hash);

    if (rc == BPAK_OK)
        rc = bpak_hash_final(&hash, hash_buffer, hash_buffer_length, NULL);

err_free_hash_ctx_out:
    bpak_hash_free(&hash);
    return rc;
}
