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
#include <bpak/crypto.h>
#include <bpak/keystore.h>

BPAK_EXPORT int bpak_pkg_sign(struct bpak_package *pkg,
                              const char *key_filename)
{
    int rc;
    struct bpak_key *sign_key = NULL;
    uint8_t hash_output[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash_output);

    rc = bpak_pkg_update_hash(pkg, (char *)hash_output, &hash_size);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_crypto_load_private_key(key_filename, &sign_key);

    if (rc != BPAK_OK) {
        return rc;
    }

    memset(pkg->header.signature, 0, sizeof(pkg->header.signature));

    size_t signature_length = sizeof(pkg->header.signature);

    rc = bpak_crypto_sign(hash_output,
                          hash_size,
                          pkg->header.hash_kind,
                          sign_key,
                          pkg->header.signature,
                          &signature_length);

    if (rc != BPAK_OK)
        goto err_free_key_out;

    pkg->header.signature_sz = (uint16_t)signature_length;

    rc = bpak_pkg_write_header(pkg);

    if (rc != BPAK_OK)
        goto err_free_key_out;

err_free_key_out:
    bpak_free(sign_key);
    return rc;
}
