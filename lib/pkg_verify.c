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

    switch (bpak_hash_kind) {
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
            return -BPAK_FAILED;
    }

    return hash_kind;
}

static int load_public_key(const char *filename, struct bpak_key **k)
{
    int rc = BPAK_OK;
    char tmp[4096];
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    mbedtls_pk_parse_public_keyfile(&ctx, filename);

    int len = mbedtls_pk_write_pubkey_der(&ctx, tmp, sizeof(tmp));

    if (len < 0) {
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx;
    }

    *k = malloc(sizeof(struct bpak_key) + len);
    struct bpak_key *key = *k;
    key->size = len;

    if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0) {
        switch (mbedtls_pk_get_bitlen(&ctx)) {
            case 256:
                key->kind = BPAK_KEY_PUB_PRIME256v1;
            break;
            case 384:
                key->kind = BPAK_KEY_PUB_SECP384r1;
            break;
            case 521:
                key->kind = BPAK_KEY_PUB_SECP521r1;
            break;
            default:
                rc = -BPAK_UNSUPPORTED_KEY;
                goto err_free_ctx;
        };
    } else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0) {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096) {
            key->kind = BPAK_KEY_PUB_RSA4096;
        } else {
            rc = -BPAK_UNSUPPORTED_KEY;
            goto err_free_ctx;
        }
    } else {
        rc = -BPAK_UNSUPPORTED_KEY;
        goto err_free_ctx;
    }

    memcpy(key->data, &tmp[sizeof(tmp) - len], len);
err_free_ctx:
    mbedtls_pk_free(&ctx);
    return rc;
}

int bpak_pkg_verify(struct bpak_package *pkg, const char *key_filename)
{
    int rc;
    uint8_t hash_output[128];
    uint8_t sig[1024];
    size_t sig_size;
    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    sig_size = sizeof(sig);

    rc = bpak_copyz_signature(&pkg->header, sig, &sig_size);

    if (rc != BPAK_OK)
        goto err_out;

    struct bpak_header *h = bpak_pkg_header(pkg);

    size_t hash_size = sizeof(hash_output);
    /* Update the header hash and payload hash */
    bpak_pkg_compute_header_hash(pkg, hash_output, &hash_size, true);

    struct bpak_key *key = NULL;
    rc = load_public_key(key_filename, &key);

    if (rc != BPAK_OK)
        goto err_out;

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

    rc = mbedtls_pk_parse_public_key(&ctx, key->data, key->size);

    if (rc != 0) {
        rc = -BPAK_KEY_DECODE;
        goto err_free_crypto_ctx_out;
    }

    rc = mbedtls_pk_verify(&ctx, hash_kind(pkg->header.hash_kind),
                            hash_output, hash_size,
                            sig, sig_size);

    if (rc != BPAK_OK) {
        rc = -BPAK_VERIFY_FAIL;
        goto err_free_crypto_ctx_out;
    }

err_free_crypto_ctx_out:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&ctx);
err_free_key_out:
    free(key);
err_out:
    return rc;
}