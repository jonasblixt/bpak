#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>

#if BPAK_CONFIG_MBEDTLS == 1
#   include "mbedtls_wrapper.h"
    static bpak_hash_init_func_t _hash_init = bpak_mbed_hash_init;
    static bpak_hash_update_func_t _hash_update = bpak_mbed_hash_update;
    static bpak_hash_final_func_t _hash_final = bpak_mbed_hash_final;
    static bpak_hash_free_func_t _hash_free = bpak_mbed_hash_free;
    static bpak_crypto_verify_func_t _crypto_verify = bpak_mbed_verify;
    static bpak_crypto_sign_func_t _crypto_sign = bpak_mbed_sign;
    static bpak_crypto_load_key_func_t _crypto_load_public_key = bpak_mbed_load_public_key;
    static bpak_crypto_load_key_func_t _crypto_load_private_key = bpak_mbed_load_private_key;
    static bpak_crypto_parse_key_func_t _crypto_parse_public_key = bpak_mbed_parse_public_key;
#else
    static bpak_hash_init_func_t _hash_init = NULL;
    static bpak_hash_update_func_t _hash_update = NULL;
    static bpak_hash_final_func_t _hash_final = NULL;
    static bpak_hash_free_func_t _hash_free = NULL;
    static bpak_crypto_verify_func_t _crypto_verify = NULL;
    static bpak_crypto_sign_func_t _crypto_sign = NULL;
    static bpak_crypto_load_key_func_t _crypto_load_public_key = NULL;
    static bpak_crypto_load_key_func_t _crypto_load_private_key = NULL;
    static bpak_crypto_parse_key_func_t _crypto_parse_public_key = NULL;
#endif


BPAK_EXPORT int bpak_hash_init(struct bpak_hash_context *ctx,
                    enum bpak_hash_kind kind)
{
    if (_hash_init == NULL)
        return -BPAK_NOT_SUPPORTED;
    memset(ctx, 0, sizeof(*ctx));
    ctx->kind = kind;
    return _hash_init(ctx);
}

BPAK_EXPORT int bpak_hash_update(struct bpak_hash_context *ctx,
                     const uint8_t *buffer,
                     size_t length)
{
    if (_hash_update == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _hash_update(ctx, buffer, length);
}

BPAK_EXPORT int bpak_hash_final(struct bpak_hash_context *ctx,
                    uint8_t *buffer,
                    size_t buffer_length,
                    size_t *result_length)
{
    if (_hash_final == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _hash_final(ctx, buffer, buffer_length, result_length);
}

BPAK_EXPORT void bpak_hash_free(struct bpak_hash_context *ctx)
{
    if (_hash_free != NULL)
        _hash_free(ctx);
}

BPAK_EXPORT void bpak_hash_setup(bpak_hash_init_func_t init_func,
                    bpak_hash_update_func_t update_func,
                    bpak_hash_final_func_t final_func,
                    bpak_hash_free_func_t free_func)
{
    _hash_init = init_func;
    _hash_update = update_func;
    _hash_final = final_func;
    _hash_free = free_func;
}

BPAK_EXPORT int bpak_crypto_verify(const uint8_t *signature,
                                   size_t signature_length,
                                   const uint8_t *hash,
                                   size_t hash_length,
                                   enum bpak_hash_kind kind,
                                   struct bpak_key *key,
                                   bool *verified)
{
    if (_crypto_verify == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _crypto_verify(signature,
                          signature_length,
                          hash,
                          hash_length,
                          kind,
                          key,
                          verified);
}

BPAK_EXPORT int bpak_crypto_sign(const uint8_t *hash,
                                   size_t hash_length,
                                   enum bpak_hash_kind kind,
                                   struct bpak_key *key,
                                   uint8_t *signature,
                                   size_t *signature_length)
{
    if (_crypto_sign == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _crypto_sign(hash,
                          hash_length,
                          kind,
                          key,
                          signature,
                          signature_length);
}

BPAK_EXPORT int bpak_crypto_load_public_key(const char *filename,
                                            struct bpak_key **output)
{
    if (_crypto_load_public_key == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _crypto_load_public_key(filename, output);
}

BPAK_EXPORT int bpak_crypto_load_private_key(const char *filename,
                                             struct bpak_key **output)
{
    if (_crypto_load_private_key == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _crypto_load_private_key(filename, output);
}

BPAK_EXPORT int bpak_crypto_parse_public_key(const uint8_t *buffer,
                                             size_t length,
                                             struct bpak_key **output)
{
    if (_crypto_parse_public_key == NULL)
        return -BPAK_NOT_SUPPORTED;
    return _crypto_parse_public_key(buffer, length, output);
}

BPAK_EXPORT void bpak_crypto_setup(bpak_crypto_verify_func_t verify_func,
                                   bpak_crypto_sign_func_t sign_func,
                                   bpak_crypto_load_key_func_t load_pub_key_func,
                                   bpak_crypto_load_key_func_t load_pri_key_func,
                                   bpak_crypto_parse_key_func_t parse_pub_key_func)
{
    _crypto_verify = verify_func;
    _crypto_sign = sign_func;
    _crypto_load_public_key = load_pub_key_func;
    _crypto_load_private_key = load_pri_key_func;
    _crypto_parse_public_key = parse_pub_key_func;
}
