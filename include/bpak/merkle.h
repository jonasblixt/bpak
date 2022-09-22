/**
 * \file merkle.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_MERKLE_H_
#define INCLUDE_BPAK_MERKLE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <bpak/bpak.h>
#include <mbedtls/sha256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BPAK_MERKLE_BLOCK_SZ 4096
/* Maximum input data length is 1 TiB with four hash levels */
#define BPAK_MERKLE_MAX_LEVELS 4
#define BPAK_MERKLE_BLOCK_BITS 12
#define BPAK_MERKLE_HASH_BYTES 32

/**
 * \typedef bpak_merkle_hash_t
 * Only sha256 is used in this implementation
 */
typedef unsigned char bpak_merkle_hash_t[BPAK_MERKLE_HASH_BYTES];

struct bpak_merkle_context
{
    mbedtls_sha256_context running_hash;
    uint8_t buffer[BPAK_MERKLE_HASH_BYTES];
    size_t level_length[BPAK_MERKLE_MAX_LEVELS];
    off_t level_offset[BPAK_MERKLE_MAX_LEVELS];
    unsigned int no_of_levels;
    size_t input_chunk_counter;
    size_t block_byte_counter;
    size_t input_data_length;          /*!< Total size of the input filesystem in bytes */
    size_t hash_tree_length;           /*!< Hash tree output size */
    size_t salt_length;
    bool finished;
    uint8_t salt[32];                  /*!< Input salt for hashing */
    bpak_io_t wr;                      /*!< Function to write to the hash tree */
    bpak_io_t rd;                      /*!< Function to read from the hash tree */
    off_t offset;
    void *priv;                        /*!< Externalt context variable */
};

ssize_t bpak_merkle_compute_size(size_t input_data_length);

/**
 * Returns the total size in bytes of the hash tree
 *
 * @param[in] ctx Context
 *
 * @return Size in bytes
 */
size_t bpak_merkle_get_size(struct bpak_merkle_context *ctx);

/**
 * Initializes the merkle algorithm
 *
 * @param[in] ctx Context
 * @param[in] input_data_length Size of filesystem in bytes
 * @param[in] salt Salt to use for hash computation
 * @param[in] salt_length Length of salt in bytes
 * @param[in] wr Write callback function
 * @param[in] rd Read callback function
 * @param[in] offset Offset where hash tree data starts
 * @param[in] priv Optional private context
 *
 * @return BPAK_OK on success and non zero number on error
 *
 */
int bpak_merkle_init(struct bpak_merkle_context *ctx,
                        size_t input_data_length,
                        const uint8_t *salt,
                        size_t salt_length,
                        bpak_io_t wr,
                        bpak_io_t rd,
                        off_t offset,
                        bool zero_fill_output,
                        void *priv);

/**
 * Process input data stream. This function can also be called with no buffer
 * and \ref sz set to zero to complete the hash tree computation.
 *
 * @param[in] ctx Context
 * @param[in] buffer Input data buffer
 * @param[in] length Available bytes in buffer
 *
 * @return BPAK_OK on success
 */
int bpak_merkle_write_chunk(struct bpak_merkle_context *ctx, uint8_t *buffer,
                            size_t length);

/**
 * Outputs the root hash when the tree is computed
 *
 * @param[in] ctx Context
 * @param[out] roothash Root hash output
 *
 * @return BPAK_OK on success
 */
int bpak_merkle_finish(struct bpak_merkle_context *ctx,
                        bpak_merkle_hash_t roothash);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_MERKLE_H_
