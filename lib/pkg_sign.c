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

/* The signature kind of a private key */
static int signature_kind_of_key(enum bpak_key_kind kind, uint8_t *output)
{
    switch (kind) {
    case BPAK_KEY_PRI_RSA4096:
        *output = BPAK_SIGN_RSA4096;
        break;
    case BPAK_KEY_PRI_PRIME256v1:
        *output = BPAK_SIGN_PRIME256v1;
        break;
    case BPAK_KEY_PRI_SECP384r1:
        *output = BPAK_SIGN_SECP384r1;
        break;
    case BPAK_KEY_PRI_SECP521r1:
        *output = BPAK_SIGN_SECP521r1;
        break;
    default:
        return -BPAK_UNSUPPORTED_KEY;
    }

    return BPAK_OK;
}

/* Clear memory that the compiler may not optimize away */
static void zeroize(void *ptr, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    while (length--)
        *p++ = 0;
}

BPAK_EXPORT int bpak_pkg_sign(struct bpak_package *pkg,
                              const char *key_filename)
{
    int rc;
    struct bpak_key *sign_key = NULL;
    uint8_t hash_output[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash_output);
    uint8_t signature[BPAK_SIGNATURE_MAX_BYTES];
    size_t signature_length = sizeof(signature);
    uint8_t signature_kind;
    uint8_t old_signature_kind = pkg->header.signature_kind;

    rc = bpak_crypto_load_private_key(key_filename, &sign_key);

    if (rc != BPAK_OK) {
        return rc;
    }

    rc = signature_kind_of_key(sign_key->kind, &signature_kind);

    if (rc != BPAK_OK)
        goto err_free_key_out;

    /* The signature kind is covered by the header hash */
    pkg->header.signature_kind = signature_kind;

    rc = bpak_pkg_update_hash(pkg, (char *)hash_output, &hash_size);

    if (rc != BPAK_OK)
        goto err_restore_out;

    rc = bpak_crypto_sign(hash_output,
                          hash_size,
                          pkg->header.hash_kind,
                          sign_key,
                          signature,
                          &signature_length);

    if (rc != BPAK_OK)
        goto err_restore_out;

    /* The header is changed when the signature exists */
    rc = bpak_pkg_write_raw_signature(pkg, signature, signature_length);
    goto err_free_key_out;

err_restore_out:
    pkg->header.signature_kind = old_signature_kind;
err_free_key_out:
    zeroize(sign_key, sizeof(*sign_key) + sign_key->size);
    bpak_free(sign_key);
    return rc;
}
