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

#include <mbedtls/version.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/keystore.h>

static int hash_kind(int bpak_hash_kind)
{
    int hash_kind = 0;

    switch (bpak_hash_kind)
    {
        case BPAK_HASH_SHA256:
            hash_kind = MBEDTLS_MD_SHA256;
        break;
        case BPAK_HASH_SHA384:
            hash_kind = MBEDTLS_MD_SHA384;
        break;
        case BPAK_HASH_SHA512:
            hash_kind = MBEDTLS_MD_SHA512;
        break;
        default:
            return -BPAK_UNSUPPORTED_HASH_ALG;
    }

    return hash_kind;
}

static int load_private_key(const char *filename, struct bpak_key **k)
{
    int rc = BPAK_OK;
    unsigned char tmp[4096];
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "mbedtls_pk_sign";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));

    if (rc != 0) {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    rc = mbedtls_pk_parse_keyfile(&ctx,
                                  filename,
                                  NULL,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    rc = mbedtls_pk_parse_keyfile(&ctx, filename, NULL);
#endif

    int len = mbedtls_pk_write_key_der(&ctx, tmp, sizeof(tmp));

    if (len < 0) {
        bpak_printf(0, "Error: Could not load private key (%i)\n", len);
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    bpak_printf(1, "Loaded private key %i bytes\n", len);

    struct bpak_key *key = bpak_calloc(sizeof(struct bpak_key) + len, 1);
    (*k) = NULL;

    if (key == NULL) {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    (*k) = key;
    key->size = len;

    if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0) {
        switch (mbedtls_pk_get_bitlen(&ctx)) {
            case 256:
                key->kind = BPAK_KEY_PRI_PRIME256v1;
            break;
            case 384:
                key->kind = BPAK_KEY_PRI_SECP384r1;
            break;
            case 521:
                key->kind = BPAK_KEY_PRI_SECP521r1;
            break;
            default:
                bpak_printf(0, "Unknown bit-length (%li)\n",
                        mbedtls_pk_get_bitlen(&ctx));
                rc = -BPAK_KEY_DECODE;
                goto err_free_key_out;
        };
    } else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0) {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096) {
            key->kind = BPAK_KEY_PRI_RSA4096;
        } else {
            bpak_printf(0, "Unknown bit-length (%li)\n",
                    mbedtls_pk_get_bitlen(&ctx));
            rc = -BPAK_KEY_DECODE;
            goto err_free_key_out;
        }
    } else {
        bpak_printf(0, "Error: Unknown key type (%s)\n", mbedtls_pk_get_name(&ctx));
        rc = -BPAK_KEY_DECODE;
        goto err_free_key_out;
    }
    memcpy(key->data, &tmp[sizeof(tmp) - len], len);


    mbedtls_pk_free(&ctx);
    return rc;

err_free_key_out:
    bpak_free(key);
err_free_ctx_out:
    mbedtls_pk_free(&ctx);
    return rc;
}

int bpak_pkg_sign(struct bpak_package *pkg, const char *key_filename)
{
    int rc;
    struct bpak_key *sign_key = NULL;
    uint8_t hash_output[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash_output);
    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    rc = bpak_pkg_update_hash(pkg, (char *) hash_output, &hash_size);

    if (rc != BPAK_OK)
        goto err_out;

    rc = load_private_key(key_filename, &sign_key);

    if (rc != BPAK_OK) {
        goto err_out;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&ctx);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));

    if (rc != 0) {
        rc = -BPAK_FAILED;
        goto err_free_crypto_ctx_out;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_parse_key(&ctx, sign_key->data, sign_key->size,
                                NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    rc = mbedtls_pk_parse_key(&ctx, sign_key->data, sign_key->size,
                                NULL, 0);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Key parse (mbedtls: %i)\n", rc);
        rc = -BPAK_KEY_DECODE;
        goto err_free_crypto_ctx_out;
    }

    memset(pkg->header.signature, 0, sizeof(pkg->header.signature));

#if MBEDTLS_VERSION_MAJOR >= 3
    size_t signature_size = 0;

    rc = mbedtls_pk_sign(&ctx, hash_kind(pkg->header.hash_kind),
                        hash_output, hash_size,
                        pkg->header.signature, 
                        sizeof(pkg->header.signature),
                        &signature_size,
                        mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    size_t signature_size = sizeof(pkg->header.signature);

    rc = mbedtls_pk_sign(&ctx, hash_kind(pkg->header.hash_kind),
                        hash_output, hash_size,
                        pkg->header.signature, 
                        &signature_size,
                        mbedtls_ctr_drbg_random, &ctr_drbg);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Signing failed (mbedtls: %i)\n", rc);
        rc = -BPAK_SIGN_FAIL;
        goto err_free_crypto_ctx_out;
    }

    pkg->header.signature_sz = (uint16_t) signature_size;

err_free_crypto_ctx_out:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&ctx);
    bpak_free(sign_key);
err_out:
    return rc;
}
