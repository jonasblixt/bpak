/**
 * \file merkle.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_MERKLE_H_
#define INCLUDE_BPAK_MERKLE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/**
 * \def MERKLE_BLOCK_SZ
 * Size of hash blocks in bytes. This is selected to be compatible with
 *  linux dm-verity.
 *
 * \def MERKLE_MAX_LEVELS
 * Maximum hash tree depth
 *
 **/

#define MERKLE_BLOCK_SZ 4096
#define MERKLE_MAX_LEVELS 10

/**
 * \typedef bpak_merkle_hash_t
 * Only sha256 is used in this implementation
 */
typedef unsigned char bpak_merkle_hash_t[32];

/**
 * \typedef bpak_merkle_io_t
 *
 * Read or write function pointer. This is externally defined to support
 * several use-cases and not only file based io.
 */
struct bpak_merkle_context;
typedef int (*bpak_merkle_io_t) (struct bpak_merkle_context *ctx,
                                    uint64_t offset,
                                    uint8_t *buf,
                                    size_t size,
                                    void *priv);

/**
 * \typedef bpak_merkle_status_t
 *
 * Optional callback type to give feedback on progress of the algorithm.
 */
typedef void (*bpak_merkle_status_t) (struct bpak_merkle_context *ctx);

struct bpak_merkle_level
{
    int level;             /*!< Depth in the hash tree */
    uint64_t size;         /*!< Bytes at this level */
    uint64_t byte_counter; /*!< Number of bytes in hashes that have been generated */
    uint64_t offset;       /*!< Output offset */
    uint64_t padded_size;
};

struct bpak_merkle_context
{
    uint8_t buffer[MERKLE_BLOCK_SZ];   /*!< Holds one block of data for hash input */
    int level;                         /*!< Current level in the hash tree */
    int no_of_levels;                  /*!< Number of levels to compute */
    struct bpak_merkle_level current;  /*!< Current, active level thats being computed */
    struct bpak_merkle_level previous; /*!< Previous level */
    size_t fs_size;                    /*!< Total size of the input filesystem in bytes */
    size_t hash_tree_size;             /*!< Hash tree output size */
    bpak_merkle_hash_t salt;           /*!< Input salt for hashing */
    bpak_merkle_hash_t hash;           /*!< Output root hash */
    bpak_merkle_io_t wr;               /*!< Function to write to the hash tree */
    bpak_merkle_io_t rd;               /*!< Function to read from the hash tree */
    bpak_merkle_status_t status;       /*!< Status callback */
    void *priv;                        /*!< Externalt context variable */
};

/**
 * Compute the required size in bytes for a given level.
 *
 * @param[in] input_data_size The size of the input data
 * @param[in] level Which level to compute size requirement for
 * @param[in] pad Pad the required data to the nearest block alignment
 * 
 * @return Size in bytes for a specific level in the hash tree
 */
size_t bpak_merkle_compute_size(size_t input_data_size, int level, bool pad);

/**
 * Returns the total size in bytes of the hash tree
 *
 * @param[in] ctx Context
 *
 * @return Size in bytes
 */
size_t bpak_merkle_get_size(struct bpak_merkle_context *ctx);

/**
 * Can be called to understand if additional calls to \ref bpak_merkle_process
 *  is needed to complete hash tree.
 *
 *  @param[in] ctx Context
 *
 *  @return True if more computation needs to be done
 */
bool bpak_merkle_done(struct bpak_merkle_context *ctx);

/**
 * Initializes the merkle algorithm
 *
 * @param[in] ctx Context
 * @param[in] filesystem_size Size of filesystem in bytes
 * @param[in] salt Salt to use for hash computation
 * @param[in] wr Write callback function
 * @param[in] rd Read callback function
 * @param[in] priv Optional private context
 *
 * @return BPAK_OK on success and non zero number on error
 *
 */
int bpak_merkle_init(struct bpak_merkle_context *ctx,
                        size_t filesystem_size,
                        bpak_merkle_hash_t salt,
                        bpak_merkle_io_t wr,
                        bpak_merkle_io_t rd,
                        void *priv);

/**
 * Set an optional status callback function
 *
 * @param[in] ctx Context
 * @param[in] sts Status function pointer
 *
 * @return BPAK_OK on success
 */
int bpak_merkle_set_status_cb(struct bpak_merkle_context *ctx,
                              bpak_merkle_status_t sts);

/**
 * Process input data stream. This function can also be called with no buffer
 * and \ref sz set to zero to complete the hash tree computation.
 *
 * @param[in] ctx Context
 * @param[in] input Input data buffer
 * @param[in] sz Available bytes in buffer
 *
 * @return BPAK_OK on success
 */
int bpak_merkle_process(struct bpak_merkle_context *ctx,
                            uint8_t *input, uint16_t sz);

/**
 * Outputs the root hash when the tree is computed
 *
 * @param[in] ctx Context
 * @param[out] roothash Root hash output
 *
 * @return BPAK_OK on success
 */
int bpak_merkle_out(struct bpak_merkle_context *ctx,
                    bpak_merkle_hash_t roothash);

#endif  // INCLUDE_BPAK_MERKLE_H_
