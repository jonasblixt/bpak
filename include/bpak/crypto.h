#ifndef INCLUDE_BPAK_CRYPTO_H_
#define INCLUDE_BPAK_CRYPTO_H_

#include <bpak/bpak.h>
#include <bpak/keystore.h>

#define BPAK_HASH_MAX_SZ 64

struct bpak_ec_pub_key
{
    enum bpak_key_kind kind;
    union
    {
        uint8_t rsa[512];
        struct
        {
            uint8_t x[32];
            uint8_t y[32];
        } prime256v1;
        struct
        {
            uint8_t x[48];
            uint8_t y[48];
        } secp384r1;
        struct
        {
            uint8_t x[66];
            uint8_t y[66];
        } secp521r1;
    } key;
};

struct bpak_hash_context
{
    enum bpak_hash_kind kind;
    uint16_t size;
    uint8_t hash[BPAK_HASH_MAX_SZ];
    void *priv;
};

struct bpak_sign_context
{
    struct bpak_key *key;
    void *priv;
};

int bpak_hash_init(struct bpak_hash_context *ctx, enum bpak_hash_kind kind);
int bpak_hash_update(struct bpak_hash_context *ctx, void *ptr, size_t size);
int bpak_hash_out(struct bpak_hash_context *ctx, uint8_t *out, size_t size);
int bpak_hash_free(struct bpak_hash_context *ctx);

int bpak_sign_init(struct bpak_sign_context *ctx, struct bpak_key *key);

int bpak_sign(struct bpak_sign_context *ctx,
               struct bpak_hash_context *hash_ctx,
               uint8_t *sig, size_t *size);

int bpak_verify(struct bpak_sign_context *ctx,
                struct bpak_hash_context *hash_ctx,
                const uint8_t *sig, size_t size);
int bpak_sign_free(struct bpak_sign_context *ctx);

#endif  // INCLUDE_BPAK_CRYPTO_H_
