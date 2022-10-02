/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/keystore.h>
#include <bpak/id.h>
#include <bpak/crypto.h>

BPAK_EXPORT int bpak_keystore_get(struct bpak_keystore *ks, uint32_t id,
                      struct bpak_key **k)
{
    *k = NULL;

    if (!ks->verified)
        return -BPAK_FAILED;

    for (unsigned int i = 0; i < ks->no_of_keys; i++) {
        if (ks->keys[i]->id == id) {
            *k = ks->keys[i];
            return BPAK_OK;
        }
    }

    return -BPAK_KEY_NOT_FOUND;
}

BPAK_EXPORT int bpak_keystore_load_key_from_file(const char *filename,
                                                 uint32_t keystore_id,
                                                 uint32_t key_id,
                                                 bpak_check_header_t check_header,
                                                 void *user,
                                                 struct bpak_key **output)
{
    int rc;
    uint8_t key_buffer[512];
    struct bpak_package pkg;
    struct bpak_part_header *key_part = NULL;
    size_t key_length;
    uint32_t *keystore_provider_id = NULL;

    rc = bpak_pkg_open(&pkg, filename, "rb");

    if (rc != BPAK_OK)
        return rc;

    /* Optionally verify other meta data in the header */
    if (check_header != NULL) {
        rc = check_header(&pkg.header, user);

        if (rc != BPAK_OK)
            goto err_close_pkg_out;
    }

    rc = bpak_get_meta(&pkg.header, BPAK_ID_KEYSTORE_PROVIDER_ID,
                                    (void **) &keystore_provider_id, NULL);

    if (rc != BPAK_OK)
        goto err_close_pkg_out;

    if (*keystore_provider_id != keystore_id) {
        rc = -BPAK_KEYSTORE_ID_MISMATCH;
        goto err_close_pkg_out;
    }

    rc = bpak_get_part(&pkg.header, key_id, &key_part, NULL);

    if (rc != BPAK_OK)
        goto err_close_pkg_out;

    key_length = bpak_part_size_wo_pad(key_part);

    if (fseek(pkg.fp, bpak_part_offset(&pkg.header, key_part), SEEK_SET) != 0) {
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
