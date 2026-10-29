#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include <mbedtls/version.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "crypto_mbedtls.h"

#if MBEDTLS_VERSION_MAJOR < 3
#define mbedtls_sha256_starts mbedtls_sha256_starts_ret
#define mbedtls_sha256_update mbedtls_sha256_update_ret
#define mbedtls_sha256_finish mbedtls_sha256_finish_ret
#define mbedtls_sha512_starts mbedtls_sha512_starts_ret
#define mbedtls_sha512_update mbedtls_sha512_update_ret
#define mbedtls_sha512_finish mbedtls_sha512_finish_ret
#endif

int bpak_mbed_hash_init(struct bpak_hash_context *ctx)
{
    int rc;

    switch (ctx->kind) {
    case BPAK_HASH_SHA256:
        mbedtls_sha256_init(&ctx->backend.mbed_sha256);
        rc = mbedtls_sha256_starts(&ctx->backend.mbed_sha256, 0);
        break;
    case BPAK_HASH_SHA384:
        mbedtls_sha512_init(&ctx->backend.mbed_sha512);
        rc = mbedtls_sha512_starts(&ctx->backend.mbed_sha512, 1);
        break;
    case BPAK_HASH_SHA512:
        mbedtls_sha512_init(&ctx->backend.mbed_sha512);
        rc = mbedtls_sha512_starts(&ctx->backend.mbed_sha512, 0);
        break;
    default:
        return -BPAK_UNSUPPORTED_HASH_ALG;
    }

    return (rc == 0) ? BPAK_OK : -BPAK_FAILED;
}

int bpak_mbed_hash_update(struct bpak_hash_context *ctx, const uint8_t *buffer,
                          size_t length)
{
    int rc;

    if (ctx->kind == BPAK_HASH_SHA256)
        rc = mbedtls_sha256_update(&ctx->backend.mbed_sha256,
                                   (const unsigned char *)buffer,
                                   length);
    else
        rc = mbedtls_sha512_update(&ctx->backend.mbed_sha512,
                                   (const unsigned char *)buffer,
                                   length);

    return (rc == 0) ? BPAK_OK : -BPAK_FAILED;
}

int bpak_mbed_hash_final(struct bpak_hash_context *ctx, uint8_t *buffer,
                         size_t buffer_length, size_t *result_length)
{
    int rc;
    size_t length;

    switch (ctx->kind) {
    case BPAK_HASH_SHA256:
        length = 32;
        break;
    case BPAK_HASH_SHA384:
        length = 48;
        break;
    case BPAK_HASH_SHA512:
        length = 64;
        break;
    default:
        return -BPAK_UNSUPPORTED_HASH_ALG;
    }

    if (buffer_length < length)
        return -BPAK_SIZE_ERROR;

    if (ctx->kind == BPAK_HASH_SHA256)
        rc = mbedtls_sha256_finish(&ctx->backend.mbed_sha256,
                                   (unsigned char *)buffer);
    else
        rc = mbedtls_sha512_finish(&ctx->backend.mbed_sha512,
                                   (unsigned char *)buffer);

    if (rc != 0)
        return -BPAK_FAILED;

    if (result_length != NULL)
        (*result_length) = length;

    return BPAK_OK;
}

void bpak_mbed_hash_free(struct bpak_hash_context *ctx)
{
    switch (ctx->kind) {
    case BPAK_HASH_SHA256:
        mbedtls_sha256_free(&ctx->backend.mbed_sha256);
        break;
    case BPAK_HASH_SHA384:
    case BPAK_HASH_SHA512:
        mbedtls_sha512_free(&ctx->backend.mbed_sha512);
        break;
    default:
        break;
    }
}

static int hash_kind(int bpak_hash_kind, mbedtls_md_type_t *md_type)
{
    switch (bpak_hash_kind) {
    case BPAK_HASH_SHA256:
        *md_type = MBEDTLS_MD_SHA256;
        break;
    case BPAK_HASH_SHA384:
        *md_type = MBEDTLS_MD_SHA384;
        break;
    case BPAK_HASH_SHA512:
        *md_type = MBEDTLS_MD_SHA512;
        break;
    default:
        return -BPAK_UNSUPPORTED_HASH_ALG;
    }

    return BPAK_OK;
}

int bpak_mbed_verify(const uint8_t *signature, size_t signature_length,
                     const uint8_t *hash, size_t hash_length,
                     enum bpak_hash_kind kind, struct bpak_key *key,
                     bool *verified)
{
    int rc;
    mbedtls_pk_context ctx;
    mbedtls_md_type_t md_type;

    (*verified) = false;

    rc = hash_kind(kind, &md_type);

    if (rc != BPAK_OK)
        return rc;

    mbedtls_pk_init(&ctx);

    rc = mbedtls_pk_parse_public_key(&ctx, key->data, key->size);

    if (rc != 0) {
        mbedtls_pk_free(&ctx);
        return -BPAK_KEY_DECODE;
    }

    /* A signature that does not match is not an error, see
     * bpak_crypto_verify() */
    rc = mbedtls_pk_verify(&ctx,
                           md_type,
                           (unsigned char *)hash,
                           hash_length,
                           (unsigned char *)signature,
                           signature_length);

    (*verified) = (rc == 0);

    mbedtls_pk_free(&ctx);
    return BPAK_OK;
}

int bpak_mbed_sign(const uint8_t *hash, size_t hash_length,
                   enum bpak_hash_kind kind, struct bpak_key *key,
                   uint8_t *signature, size_t *signature_length)
{
    int rc;
    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_md_type_t md_type;

    rc = hash_kind(kind, &md_type);

    if (rc != BPAK_OK)
        return rc;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&ctx);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg,
                               mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *)pers,
                               strlen(pers));

    if (rc != 0) {
        rc = -BPAK_FAILED;
        goto err_free_crypto_ctx_out;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_parse_key(&ctx,
                              key->data,
                              key->size,
                              NULL,
                              0,
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg);
#else
    rc = mbedtls_pk_parse_key(&ctx, key->data, key->size, NULL, 0);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Key parse (mbedtls: %i)\n", rc);
        rc = -BPAK_KEY_DECODE;
        goto err_free_crypto_ctx_out;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_sign(&ctx,
                         md_type,
                         hash,
                         hash_length,
                         signature,
                         *signature_length,
                         signature_length,
                         mbedtls_ctr_drbg_random,
                         &ctr_drbg);
#else
    rc = mbedtls_pk_sign(&ctx,
                         md_type,
                         hash,
                         hash_length,
                         signature,
                         signature_length,
                         mbedtls_ctr_drbg_random,
                         &ctr_drbg);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Signing failed (mbedtls: %i)\n", rc);
        rc = -BPAK_SIGN_FAIL;
        goto err_free_crypto_ctx_out;
    }

err_free_crypto_ctx_out:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&ctx);
    return rc;
}

int bpak_mbed_load_public_key(const char *filename, struct bpak_key **output)
{
    int rc = BPAK_OK;
    unsigned char tmp[1024];
    struct bpak_key *key = NULL;
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    if (mbedtls_pk_parse_public_keyfile(&ctx, filename) != 0) {
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx;
    }

    int len = mbedtls_pk_write_pubkey_der(&ctx, tmp, sizeof(tmp));

    if (len < 0) {
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx;
    }

    key = bpak_calloc(sizeof(struct bpak_key) + len, 1);

    if (key == NULL) {
        rc = -BPAK_FAILED;
        goto err_free_ctx;
    }

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
            goto err_free_key_out;
        };
    } else if (strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0) {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096) {
            key->kind = BPAK_KEY_PUB_RSA4096;
        } else {
            rc = -BPAK_UNSUPPORTED_KEY;
            goto err_free_key_out;
        }
    } else {
        rc = -BPAK_UNSUPPORTED_KEY;
        goto err_free_key_out;
    }

    memcpy(key->data, &tmp[sizeof(tmp) - len], len);
    (*output) = key;
    mbedtls_pk_free(&ctx);
    return BPAK_OK;

err_free_key_out:
    bpak_free(key);
err_free_ctx:
    mbedtls_pk_free(&ctx);
    return rc;
}

int bpak_mbed_load_private_key(const char *filename, struct bpak_key **output)
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

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg,
                               mbedtls_entropy_func,
                               &entropy,
                               (const unsigned char *)pers,
                               strlen(pers));

    if (rc != 0) {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    rc = mbedtls_pk_parse_keyfile(&ctx,
                                  filename,
                                  NULL,
                                  mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
#else
    rc = mbedtls_pk_parse_keyfile(&ctx, filename, NULL);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Could not load private key (mbedtls: %i)\n", rc);
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    int len = mbedtls_pk_write_key_der(&ctx, tmp, sizeof(tmp));

    if (len < 0) {
        bpak_printf(0, "Error: Could not load private key (%i)\n", len);
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    bpak_printf(1, "Loaded private key %i bytes\n", len);

    struct bpak_key *key = bpak_calloc(sizeof(struct bpak_key) + len, 1);

    if (key == NULL) {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

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
            bpak_printf(0,
                        "Unknown bit-length (%zu)\n",
                        mbedtls_pk_get_bitlen(&ctx));
            rc = -BPAK_KEY_DECODE;
            goto err_free_key_out;
        };
    } else if (strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0) {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096) {
            key->kind = BPAK_KEY_PRI_RSA4096;
        } else {
            bpak_printf(0,
                        "Unknown bit-length (%zu)\n",
                        mbedtls_pk_get_bitlen(&ctx));
            rc = -BPAK_KEY_DECODE;
            goto err_free_key_out;
        }
    } else {
        bpak_printf(0,
                    "Error: Unknown key type (%s)\n",
                    mbedtls_pk_get_name(&ctx));
        rc = -BPAK_KEY_DECODE;
        goto err_free_key_out;
    }
    memcpy(key->data, &tmp[sizeof(tmp) - len], len);
    (*output) = key;
    goto err_free_ctx_out;

err_free_key_out:
    mbedtls_platform_zeroize(key, sizeof(struct bpak_key) + len);
    bpak_free(key);
err_free_ctx_out:
    /* The DER encoded private key */
    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    mbedtls_pk_free(&ctx);
#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#endif
    return rc;
}

int bpak_mbed_parse_public_key(const uint8_t *buffer, size_t length,
                               struct bpak_key **output)
{
    int rc = BPAK_OK;
    struct bpak_key *key = NULL;
    uint8_t key_buffer[1024];
    enum bpak_key_kind kind;
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    rc = mbedtls_pk_parse_public_key(&ctx, buffer, length);

    if (rc != 0) {
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0) {
        switch (mbedtls_pk_get_bitlen(&ctx)) {
        case 256:
            kind = BPAK_KEY_PUB_PRIME256v1;
            break;
        case 384:
            kind = BPAK_KEY_PUB_SECP384r1;
            break;
        case 521:
            kind = BPAK_KEY_PUB_SECP521r1;
            break;
        default:
            rc = -BPAK_KEY_DECODE;
            goto err_free_ctx_out;
        };
    } else if (strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0) {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096) {
            kind = BPAK_KEY_PUB_RSA4096;
        } else {
            rc = -BPAK_KEY_DECODE;
            goto err_free_ctx_out;
        }
    } else {
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    int len = mbedtls_pk_write_pubkey_der(&ctx, key_buffer, sizeof(key_buffer));

    if (len < 0) {
        rc = -BPAK_KEY_DECODE;
        (*output) = NULL;
        goto err_free_ctx_out;
    }

    key = bpak_calloc(1, sizeof(struct bpak_key) + len);

    if (key == NULL) {
        rc = -BPAK_FAILED;
        goto err_free_ctx_out;
    }

    memcpy(key->data, &key_buffer[sizeof(key_buffer) - len], len);

    key->size = (uint16_t)len;
    key->kind = kind;

    (*output) = key;

err_free_ctx_out:
    mbedtls_pk_free(&ctx);
    return rc;
}
