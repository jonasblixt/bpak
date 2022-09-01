/**
 * \file verify.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_BPAK_VERIFY_H
#define INCLUDE_BPAK_BPAK_VERIFY_H

#include <stdint.h>
#include <unistd.h>
#include <bpak/bpak.h>
#include <bpak/merkle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute the hash of a bpak header
 *
 * @param[in] header Pointer to a bpak header
 * @param[out] output_hash_buffer Output hash
 * @param[in] size In/out Available bytes in buffer as input and set to
 *                          produced bytes output
 *
 * @return BPAK_OK on success
 */
int bpak_verify_compute_header_hash(struct bpak_header *header,
                                    uint8_t *output_hash_buffer,
                                    size_t *output_hash_buffer_length);

/**
 * Compute the hash the payload
 *
 * @param[in] header Pointer to a bpak header
 * @param[in] read Read callback for reading payload data
 * @param[in] data_offset Payload data offset
 * @param[in] user User pointer for io callback
 * @param[in] output_hash_buffer Output hash buffer
 * @param[in] outpu_hash_buffer_length Length of hash buffer / result bytes
 *
 * @return BPAK_OK on success
 */
int bpak_verify_compute_payload_hash(struct bpak_header *header,
                                    bpak_io_t read_payload,
                                    off_t data_offset,
                                    void *user,
                                    uint8_t *output_hash_buffer,
                                    size_t *output_hash_buffer_length);

/**
 * Verify an existing merkle hash tree. This function will re-generate all
 * hashes and compare the result with what's accesible with the 'read_payload'
 * function at offset 'tree_offset'.
 *
 * @param[in] read_payload i/o call back for reading payload data
 * @param[in] data_offset Offset where input data to merkle tree begins
 * @param[in] data_length Length of data block
 * @param[in] tree_offset Offset where merkle tree data begins
 * @param[in] expected_root_hash Expected root hash
 * @param[in] salt Salt to use during operation
 *
 * @return BPAK_OK if verification is OK
 */
int bpak_verify_merkle_tree(bpak_io_t read_payload,
                            off_t data_offset,
                            size_t data_length,
                            off_t tree_offset,
                            bpak_merkle_hash_t expected_root_hash,
                            bpak_merkle_hash_t salt,
                            void *user);

/**
 * Verify the payload data. It will compute the payload hash for parts that
 * should be hashed. It also verifies generated merkle hash trees and
 * root hashes.
 *
 * @param[in] header Pointer to a bpak header
 * @param[in] read I/O callback for reading payload data
 * @param[in] data_offset Payload data offset
 * @param[in] user User pointer for io callback
 *
 * @return BPAK_OK on success
 */
int bpak_verify_payload(struct bpak_header *header,
                        bpak_io_t read_payload,
                        off_t data_offset,
                        void *user);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_VERIFY_H
