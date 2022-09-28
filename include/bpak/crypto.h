#ifndef BPAK_CRYPTO_H
#define BPAK_CRYPTO_H

#include <bpak/bpak.h>
#include <bpak/keystore.h>

#if BPAK_CONFIG_MBEDTLS == 1
#include <mbedtls/version.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_hash_context {
    enum bpak_hash_kind kind;
    union {
        void *user_ctx;
#if BPAK_CONFIG_MBEDTLS == 1
        mbedtls_sha256_context mbed_sha256;
        mbedtls_sha512_context mbed_sha512;
#endif
    } backend;
};

typedef int (*bpak_hash_init_func_t)(struct bpak_hash_context *ctx);

typedef int (*bpak_hash_update_func_t)(struct bpak_hash_context *ctx,
                                       const uint8_t *buffer, size_t length);

typedef int (*bpak_hash_final_func_t)(struct bpak_hash_context *ctx,
                                      uint8_t *buffer, size_t buffer_length,
                                      size_t *result_length);

typedef void (*bpak_hash_free_func_t)(struct bpak_hash_context *ctx);

typedef int (*bpak_crypto_verify_func_t)(const uint8_t *signature,
                                         size_t signature_length,
                                         const uint8_t *hash,
                                         size_t hash_length,
                                         enum bpak_hash_kind kind,
                                         struct bpak_key *key, bool *verified);

typedef int (*bpak_crypto_sign_func_t)(const uint8_t *hash, size_t hash_length,
                                       enum bpak_hash_kind kind,
                                       struct bpak_key *key, uint8_t *signature,
                                       size_t *signature_length);

typedef int (*bpak_crypto_load_key_func_t)(const char *filename,
                                           struct bpak_key **output);

typedef int (*bpak_crypto_parse_key_func_t)(const uint8_t *buffer,
                                            size_t length,
                                            struct bpak_key **output);

int bpak_hash_init(struct bpak_hash_context *ctx, enum bpak_hash_kind kind);

int bpak_hash_update(struct bpak_hash_context *ctx, const uint8_t *buffer,
                     size_t length);

int bpak_hash_final(struct bpak_hash_context *ctx, uint8_t *buffer,
                    size_t buffer_length, size_t *result_length);

void bpak_hash_free(struct bpak_hash_context *ctx);

void bpak_hash_setup(bpak_hash_init_func_t init_func,
                     bpak_hash_update_func_t update_func,
                     bpak_hash_final_func_t final_func,
                     bpak_hash_free_func_t free_func);

int bpak_crypto_verify(const uint8_t *signature, size_t signature_length,
                       const uint8_t *hash, size_t hash_length,
                       enum bpak_hash_kind kind, struct bpak_key *key,
                       bool *verified);

int bpak_crypto_sign(const uint8_t *hash, size_t hash_length,
                     enum bpak_hash_kind kind, struct bpak_key *key,
                     uint8_t *signature, size_t *signature_length);

int bpak_crypto_load_public_key(const char *filename, struct bpak_key **output);
int bpak_crypto_load_private_key(const char *filename,
                                 struct bpak_key **output);
int bpak_crypto_parse_public_key(const uint8_t *buffer, size_t length,
                                 struct bpak_key **output);

void bpak_crypto_setup(bpak_crypto_verify_func_t verify_func,
                       bpak_crypto_sign_func_t sign_func,
                       bpak_crypto_load_key_func_t load_pub_key_func,
                       bpak_crypto_load_key_func_t load_pri_key_func,
                       bpak_crypto_parse_key_func_t parse_pub_key_func);

#ifdef __cplusplus
} // extern "C"
#endif
#endif
