#ifndef BPAK_MBEDTLS_WRAPPER_H
#define BPAK_MBEDTLS_WRAPPER_H

int bpak_mbed_hash_init(struct bpak_hash_context *ctx);

int bpak_mbed_hash_update(struct bpak_hash_context *ctx, const uint8_t *buffer,
                          size_t length);

int bpak_mbed_hash_final(struct bpak_hash_context *ctx, uint8_t *buffer,
                         size_t buffer_length, size_t *result_length);

void bpak_mbed_hash_free(struct bpak_hash_context *ctx);

int bpak_mbed_verify(const uint8_t *signature, size_t signature_length,
                     const uint8_t *hash, size_t hash_length,
                     enum bpak_hash_kind kind, struct bpak_key *key,
                     bool *verified);

int bpak_mbed_sign(const uint8_t *hash, size_t hash_length,
                   enum bpak_hash_kind kind, struct bpak_key *key,
                   uint8_t *signature, size_t *signature_length);

int bpak_mbed_load_public_key(const char *filename, struct bpak_key **output);
int bpak_mbed_load_private_key(const char *filename, struct bpak_key **output);
int bpak_mbed_parse_public_key(const uint8_t *buffer, size_t length,
                               struct bpak_key **output);
#endif
