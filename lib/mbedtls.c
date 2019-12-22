#include <string.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/crypto.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>



int bpak_hash_init(struct bpak_hash_context *ctx, enum bpak_hash_kind kind)
{
    ctx->kind = kind;
    memset(ctx->hash, 0, BPAK_HASH_MAX_SZ);

    switch (kind)
    {
        case BPAK_HASH_SHA256:
            ctx->priv = malloc(sizeof(mbedtls_sha256_context));
            ctx->size = 32;
            mbedtls_sha256_init(ctx->priv);
            mbedtls_sha256_starts_ret(ctx->priv, 0);
        break;
        case BPAK_HASH_SHA512:
            ctx->priv = malloc(sizeof(mbedtls_sha512_context));
            ctx->size = 64;
            mbedtls_sha512_init(ctx->priv);
            mbedtls_sha512_starts_ret(ctx->priv, 0);
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    return BPAK_OK;
}

int bpak_hash_update(struct bpak_hash_context *ctx, void *ptr, size_t size)
{
    switch (ctx->kind)
    {
        case BPAK_HASH_SHA256:
            if (mbedtls_sha256_update_ret(ctx->priv, (void *) ptr, size) != 0)
                return -BPAK_FAILED;
        break;
        case BPAK_HASH_SHA512:
            if (mbedtls_sha512_update_ret(ctx->priv, (void *) ptr, size) != 0)
                return -BPAK_FAILED;
        break;
        default:
            return -BPAK_FAILED;
    }

    return BPAK_OK;
}

int bpak_hash_out(struct bpak_hash_context *ctx, uint8_t *out, size_t size)
{
    if (size < ctx->size)
        return -BPAK_FAILED;

    switch (ctx->kind)
    {
        case BPAK_HASH_SHA256:
            if (mbedtls_sha256_finish_ret(ctx->priv, ctx->hash) != 0)
                return -BPAK_FAILED;
        break;
        case BPAK_HASH_SHA512:
            if (mbedtls_sha512_finish_ret(ctx->priv, ctx->hash) != 0)
                return -BPAK_FAILED;
        break;
        default:
            return -BPAK_FAILED;
    }

    memcpy(out, ctx->hash, ctx->size);

    return BPAK_OK;
}

int bpak_hash_free(struct bpak_hash_context *ctx)
{

    switch (ctx->kind)
    {
        case BPAK_HASH_SHA256:
            mbedtls_sha256_free(ctx->priv);
            memset(ctx->hash, 0, 32);
            free(ctx->priv);
        break;
        case BPAK_HASH_SHA512:
            mbedtls_sha512_free(ctx->priv);
            memset(ctx->hash, 0, 64);
            free(ctx->priv);
        break;
        default:
            return -BPAK_FAILED;
    }

    return BPAK_OK;
}


struct mbedtls_private_ctx
{
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

int bpak_sign_init(struct bpak_sign_context *ctx, struct bpak_key *key)
{
    int rc;
    const char *pers = "mbedtls_pk_sign";

    ctx->key = key;
    ctx->priv = malloc(sizeof(struct mbedtls_private_ctx));
    struct mbedtls_private_ctx *p = (struct mbedtls_private_ctx *) ctx->priv;

    mbedtls_entropy_init(&p->entropy);
    mbedtls_ctr_drbg_init(&p->ctr_drbg);
    mbedtls_pk_init(&p->ctx);


    rc = mbedtls_ctr_drbg_seed(&p->ctr_drbg, mbedtls_entropy_func, &p->entropy,
                               (const unsigned char *) pers,
                               strlen(pers));

    if (rc != 0)
        return -BPAK_FAILED;

    switch (key->kind)
    {
        case BPAK_KEY_PRI_RSA4096:
        case BPAK_KEY_PRI_PRIME256v1:
        case BPAK_KEY_PRI_SECP384r1:
        case BPAK_KEY_PRI_SECP521r1:
            rc = mbedtls_pk_parse_key(&p->ctx, ctx->key->data, ctx->key->size,
                                        NULL, 0);
        break;

        case BPAK_KEY_PUB_RSA4096:
        case BPAK_KEY_PUB_PRIME256v1:
        case BPAK_KEY_PUB_SECP384r1:
        case BPAK_KEY_PUB_SECP521r1:
            rc = mbedtls_pk_parse_public_key(&p->ctx, ctx->key->data,
                                                ctx->key->size);
        break;
        default:
            return -BPAK_FAILED;
    }
    if (rc != 0)
        return -BPAK_FAILED;

    return BPAK_OK;
}

int bpak_sign(struct bpak_sign_context *ctx,
               struct bpak_hash_context *hash_ctx,
               uint8_t *sig, size_t *size)
{
    int rc;
    struct mbedtls_private_ctx *p = (struct mbedtls_private_ctx *) ctx->priv;

    int hash_kind = 0;

    switch (hash_ctx->kind)
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
            return -BPAK_FAILED;
    }

    rc = mbedtls_pk_sign(&p->ctx, hash_kind,
                        hash_ctx->hash, hash_ctx->size,
                        sig, size,
                        mbedtls_ctr_drbg_random, &p->ctr_drbg);

    if (rc == 0)
        return BPAK_OK;

    return -BPAK_FAILED;
}

int bpak_verify(struct bpak_sign_context *ctx,
                    struct bpak_hash_context *hash_ctx,
                    const uint8_t *sig, size_t size)
{
    int rc;

    struct mbedtls_private_ctx *p = (struct mbedtls_private_ctx *) ctx->priv;


    int hash_kind = 0;

    switch (hash_ctx->kind)
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
            return -BPAK_FAILED;
    }

    rc = mbedtls_pk_verify(&p->ctx, hash_kind,
                            hash_ctx->hash, hash_ctx->size,
                            sig, size);

    if (rc == 0)
        return BPAK_OK;

    return -BPAK_FAILED;
}

int bpak_sign_free(struct bpak_sign_context *ctx)
{
    struct mbedtls_private_ctx *p = (struct mbedtls_private_ctx *) ctx->priv;
    mbedtls_pk_free(&p->ctx);
    mbedtls_ctr_drbg_free( &p->ctr_drbg );
    mbedtls_entropy_free( &p->entropy );
    free(ctx->priv);
    return BPAK_OK;
}
