#include <string.h>
#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/crypto.h>


int bpak_hash_init(struct bpak_hash_context *ctx, enum bpak_hash_kind kind)
{
    return -BPAK_FAILED;
}

int bpak_hash_update(struct bpak_hash_context *ctx, void *ptr, size_t size)
{
    return -BPAK_FAILED;
}

int bpak_hash_out(struct bpak_hash_context *ctx, uint8_t *out, size_t size)
{
    return -BPAK_FAILED;
}

int bpak_hash_free(struct bpak_hash_context *ctx)
{
    return -BPAK_FAILED;
}

int bpak_sign_init(struct bpak_sign_context *ctx, struct bpak_key *key)
{
    return -BPAK_FAILED;
}


int bpak_sign(struct bpak_sign_context *ctx,
               struct bpak_hash_context *hash_ctx,
               uint8_t *sig, size_t *size)
{
    return -BPAK_FAILED;
}

int bpak_verify(struct bpak_sign_context *ctx,
                    struct bpak_hash_context *hash_ctx,
                    const uint8_t *sig, size_t size)
{
    return -BPAK_FAILED;
}

int bpak_sign_free(struct bpak_sign_context *ctx)
{
    return -BPAK_FAILED;
}
