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

/* The random number generator of signing and of parsing private keys */
struct rng {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

/* Seed the generator, free it with rng_free() also when this fails */
static int rng_init(struct rng *rng)
{
    const char *pers = "mbedtls_pk_sign";

    mbedtls_entropy_init(&rng->entropy);
    mbedtls_ctr_drbg_init(&rng->ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&rng->ctr_drbg,
                              mbedtls_entropy_func,
                              &rng->entropy,
                              (const unsigned char *)pers,
                              strlen(pers)) != 0)
        return -BPAK_FAILED;

    return BPAK_OK;
}

static void rng_free(struct rng *rng)
{
    mbedtls_ctr_drbg_free(&rng->ctr_drbg);
    mbedtls_entropy_free(&rng->entropy);
}

int bpak_mbed_sign(const uint8_t *hash, size_t hash_length,
                   enum bpak_hash_kind kind, struct bpak_key *key,
                   uint8_t *signature, size_t *signature_length)
{
    int rc;
    mbedtls_pk_context ctx;
    struct rng rng;
    mbedtls_md_type_t md_type;

    rc = hash_kind(kind, &md_type);

    if (rc != BPAK_OK)
        return rc;

    mbedtls_pk_init(&ctx);
    rc = rng_init(&rng);

    if (rc != BPAK_OK)
        goto err_free_crypto_ctx_out;

#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_parse_key(&ctx,
                              key->data,
                              key->size,
                              NULL,
                              0,
                              mbedtls_ctr_drbg_random,
                              &rng.ctr_drbg);
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
                         &rng.ctr_drbg);
#else
    rc = mbedtls_pk_sign(&ctx,
                         md_type,
                         hash,
                         hash_length,
                         signature,
                         signature_length,
                         mbedtls_ctr_drbg_random,
                         &rng.ctr_drbg);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Signing failed (mbedtls: %i)\n", rc);
        rc = -BPAK_SIGN_FAIL;
        goto err_free_crypto_ctx_out;
    }

err_free_crypto_ctx_out:
    rng_free(&rng);
    mbedtls_pk_free(&ctx);
    return rc;
}

/* The kinds of keys that bpak supports */
static const struct {
    const char *name;
    size_t bitlen;
    enum bpak_key_kind public_kind;
    enum bpak_key_kind private_kind;
} key_kinds[] = {
    { "EC", 256, BPAK_KEY_PUB_PRIME256v1, BPAK_KEY_PRI_PRIME256v1 },
    { "EC", 384, BPAK_KEY_PUB_SECP384r1, BPAK_KEY_PRI_SECP384r1 },
    { "EC", 521, BPAK_KEY_PUB_SECP521r1, BPAK_KEY_PRI_SECP521r1 },
    { "RSA", 4096, BPAK_KEY_PUB_RSA4096, BPAK_KEY_PRI_RSA4096 },
};

/* Allocate a key with the DER encoding of the public or the private key in
 * 'ctx'. A key of a kind that is not supported fails with 'unsupported'. */
static int key_from_pk(mbedtls_pk_context *ctx, bool private_key,
                       int unsupported, struct bpak_key **output)
{
    int rc = unsupported;
    unsigned char der[4096];
    /* Public keys are at most 1024 bytes */
    size_t der_size = private_key ? sizeof(der) : 1024;
    struct bpak_key *key;
    size_t i;
    int len;

    if (private_key)
        len = mbedtls_pk_write_key_der(ctx, der, der_size);
    else
        len = mbedtls_pk_write_pubkey_der(ctx, der, der_size);

    if (len < 0) {
        bpak_printf(0, "Error: Could not encode the key (mbedtls: %i)\n", len);
        rc = -BPAK_KEY_DECODE;
        goto out;
    }

    for (i = 0; i < sizeof(key_kinds) / sizeof(key_kinds[0]); i++) {
        if (strcmp(mbedtls_pk_get_name(ctx), key_kinds[i].name) == 0 &&
            mbedtls_pk_get_bitlen(ctx) == key_kinds[i].bitlen)
            break;
    }

    if (i == sizeof(key_kinds) / sizeof(key_kinds[0])) {
        bpak_printf(0,
                    "Error: Unsupported key (%s, %zu bits)\n",
                    mbedtls_pk_get_name(ctx),
                    mbedtls_pk_get_bitlen(ctx));
        goto out;
    }

    key = bpak_calloc(sizeof(struct bpak_key) + len, 1);

    if (key == NULL) {
        rc = -BPAK_FAILED;
        goto out;
    }

    key->kind =
        private_key ? key_kinds[i].private_kind : key_kinds[i].public_kind;
    key->size = (uint16_t)len;
    memcpy(key->data, &der[der_size - len], len);
    (*output) = key;
    rc = BPAK_OK;

out:
    /* The DER encoded private key */
    mbedtls_platform_zeroize(der, sizeof(der));
    return rc;
}

int bpak_mbed_load_public_key(const char *filename, struct bpak_key **output)
{
    int rc = -BPAK_KEY_DECODE;
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    if (mbedtls_pk_parse_public_keyfile(&ctx, filename) == 0)
        rc = key_from_pk(&ctx, false, -BPAK_UNSUPPORTED_KEY, output);

    mbedtls_pk_free(&ctx);
    return rc;
}

int bpak_mbed_load_private_key(const char *filename, struct bpak_key **output)
{
    int rc;
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

#if MBEDTLS_VERSION_MAJOR >= 3
    struct rng rng;

    rc = rng_init(&rng);

    if (rc != BPAK_OK)
        goto err_free_ctx_out;

    rc = mbedtls_pk_parse_keyfile(&ctx,
                                  filename,
                                  NULL,
                                  mbedtls_ctr_drbg_random,
                                  &rng.ctr_drbg);
#else
    rc = mbedtls_pk_parse_keyfile(&ctx, filename, NULL);
#endif

    if (rc != 0) {
        bpak_printf(0, "Error: Could not load private key (mbedtls: %i)\n", rc);
        rc = -BPAK_KEY_DECODE;
        goto err_free_ctx_out;
    }

    rc = key_from_pk(&ctx, true, -BPAK_KEY_DECODE, output);

err_free_ctx_out:
    mbedtls_pk_free(&ctx);
#if MBEDTLS_VERSION_MAJOR >= 3
    rng_free(&rng);
#endif
    return rc;
}

int bpak_mbed_parse_public_key(const uint8_t *buffer, size_t length,
                               struct bpak_key **output)
{
    int rc = -BPAK_KEY_DECODE;
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);

    if (mbedtls_pk_parse_public_key(&ctx, buffer, length) == 0)
        rc = key_from_pk(&ctx, false, -BPAK_KEY_DECODE, output);

    mbedtls_pk_free(&ctx);
    return rc;
}
