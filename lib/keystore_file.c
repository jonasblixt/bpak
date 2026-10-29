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
#include <bpak/pkg.h>
#include <bpak/keystore.h>
#include <bpak/id.h>
#include <bpak/crypto.h>
#include <bpak/verify.h>

#include "internal.h"

BPAK_EXPORT int bpak_keystore_load_key_from_file(const char *filename,
                                                 uint32_t keystore_id,
                                                 uint32_t key_id,
                                                 bpak_check_header_t check_header,
                                                 void *user,
                                                 struct bpak_key **output)
{
    int rc;
    uint8_t key_buffer[1024];
    struct bpak_package pkg;
    struct bpak_part_header *key_part = NULL;
    uint8_t *provider_id = NULL;
    size_t key_length;
    bpak_id_t keystore_provider_id;

    rc = bpak_pkg_open(&pkg, filename, "rb");

    if (rc != BPAK_OK)
        return rc;

    /* The keystore is not signed, its payload hash detects a keystore that
     * is corrupted or truncated */
    rc = bpak_verify_payload(&pkg.header,
                             bpak_file_read,
                             sizeof(struct bpak_header),
                             pkg.fp);

    if (rc != BPAK_OK)
        goto err_close_pkg_out;

    /* Optionally verify other meta data in the header */
    if (check_header != NULL) {
        rc = check_header(&pkg.header, user);

        if (rc != BPAK_OK)
            goto err_close_pkg_out;
    }

    rc = bpak_get_meta_value(&pkg.header,
                             BPAK_ID_KEYSTORE_PROVIDER_ID,
                             0,
                             sizeof(keystore_provider_id),
                             SIZE_MAX,
                             &provider_id);

    if (rc != BPAK_OK)
        goto err_close_pkg_out;

    memcpy(&keystore_provider_id, provider_id, sizeof(keystore_provider_id));

    if (keystore_provider_id != keystore_id) {
        rc = -BPAK_KEYSTORE_ID_MISMATCH;
        goto err_close_pkg_out;
    }

    rc = bpak_get_part(&pkg.header, key_id, &key_part);

    if (rc != BPAK_OK) {
        rc = -BPAK_KEY_NOT_FOUND;
        goto err_close_pkg_out;
    }

    key_length = bpak_part_size_wo_pad(key_part);

    if (key_length > sizeof(key_buffer)) {
        rc = -BPAK_SIZE_ERROR;
        goto err_close_pkg_out;
    }

    if (fseeko(pkg.fp, bpak_part_offset(&pkg.header, key_part), SEEK_SET) !=
        0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_close_pkg_out;
    }

    if (fread(key_buffer, 1, key_length, pkg.fp) != key_length) {
        rc = -BPAK_READ_ERROR;
        goto err_close_pkg_out;
    }

    rc = bpak_crypto_parse_public_key(key_buffer, key_length, output);

    if (rc != BPAK_OK)
        goto err_close_pkg_out;

    (*output)->id = key_id;

err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
