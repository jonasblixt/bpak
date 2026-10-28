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

/**
 * Hash context, 'backend' holds the state of the hash implementation
 */
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

/* Hash and crypto implementations, see bpak_hash_setup() and
 * bpak_crypto_setup(). They have the same signature and semantics as the
 * functions that call them. */

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

/**
 * Initialize a hash context
 *
 * @param[in] ctx Hash context
 * @param[in] kind Hash algorithm
 *
 * @return BPAK_OK on success or -BPAK_NOT_SUPPORTED if there is no hash
 *         implementation
 */
int bpak_hash_init(struct bpak_hash_context *ctx, enum bpak_hash_kind kind);

/**
 * Add data to a hash
 *
 * @param[in] ctx Hash context
 * @param[in] buffer Input data
 * @param[in] length Size of input data in bytes
 *
 * @return BPAK_OK on success
 */
int bpak_hash_update(struct bpak_hash_context *ctx, const uint8_t *buffer,
                     size_t length);

/**
 * Compute the hash
 *
 * @param[in] ctx Hash context
 * @param[out] buffer Output buffer
 * @param[in] buffer_length Size of output buffer in bytes
 * @param[out] result_length Optional, size of the hash in bytes
 *
 * @return BPAK_OK on success or -BPAK_SIZE_ERROR if the buffer is too small
 */
int bpak_hash_final(struct bpak_hash_context *ctx, uint8_t *buffer,
                    size_t buffer_length, size_t *result_length);

/**
 * Free the resources of a hash context
 *
 * @param[in] ctx Hash context
 */
void bpak_hash_free(struct bpak_hash_context *ctx);

/**
 * Replace the hash implementation, for example with a hardware accelerator.
 * The default implementation uses mbedtls when the library is built with it.
 */
void bpak_hash_setup(bpak_hash_init_func_t init_func,
                     bpak_hash_update_func_t update_func,
                     bpak_hash_final_func_t final_func,
                     bpak_hash_free_func_t free_func);

/**
 * Verify a signature of a hash
 *
 * @param[in] signature Signature, DER encoded for ECDSA
 * @param[in] signature_length Size of signature in bytes
 * @param[in] hash Hash that was signed
 * @param[in] hash_length Size of hash in bytes
 * @param[in] kind Hash algorithm of 'hash'
 * @param[in] key Public key
 * @param[out] verified Set to true if the signature matches
 *
 * @return BPAK_OK if the signature could be checked, the result is in
 *         'verified', or a negative error code
 */
int bpak_crypto_verify(const uint8_t *signature, size_t signature_length,
                       const uint8_t *hash, size_t hash_length,
                       enum bpak_hash_kind kind, struct bpak_key *key,
                       bool *verified);

/**
 * Sign a hash
 *
 * @param[in] hash Hash to sign
 * @param[in] hash_length Size of hash in bytes
 * @param[in] kind Hash algorithm of 'hash'
 * @param[in] key Private key
 * @param[out] signature Output buffer for the signature
 * @param[in,out] signature_length Size of the output buffer as input and
 *                                 size of the signature as output
 *
 * @return BPAK_OK on success or a negative error code
 */
int bpak_crypto_sign(const uint8_t *hash, size_t hash_length,
                     enum bpak_hash_kind kind, struct bpak_key *key,
                     uint8_t *signature, size_t *signature_length);

/**
 * Load a PEM or DER encoded public key from a file. The key is allocated with
 * bpak_calloc() and must be freed by the caller.
 *
 * @param[in] filename Key file
 * @param[out] output The key
 *
 * @return BPAK_OK on success or a negative error code
 */
int bpak_crypto_load_public_key(const char *filename, struct bpak_key **output);

/**
 * Load a PEM or DER encoded private key from a file. The key is allocated
 * with bpak_calloc() and must be freed by the caller.
 *
 * @param[in] filename Key file
 * @param[out] output The key
 *
 * @return BPAK_OK on success or a negative error code
 */
int bpak_crypto_load_private_key(const char *filename,
                                 struct bpak_key **output);

/**
 * Parse a PEM or DER encoded public key. The key is allocated with
 * bpak_calloc() and must be freed by the caller.
 *
 * @param[in] buffer Key data
 * @param[in] length Size of key data in bytes
 * @param[out] output The key
 *
 * @return BPAK_OK on success or a negative error code
 */
int bpak_crypto_parse_public_key(const uint8_t *buffer, size_t length,
                                 struct bpak_key **output);

/**
 * Replace the signature and key implementation. The default implementation
 * uses mbedtls when the library is built with it.
 */
void bpak_crypto_setup(bpak_crypto_verify_func_t verify_func,
                       bpak_crypto_sign_func_t sign_func,
                       bpak_crypto_load_key_func_t load_pub_key_func,
                       bpak_crypto_load_key_func_t load_pri_key_func,
                       bpak_crypto_parse_key_func_t parse_pub_key_func);

#ifdef __cplusplus
} // extern "C"
#endif
#endif
