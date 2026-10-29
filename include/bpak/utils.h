/**
 * \file utils.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef INCLUDE_BPAK_UTILS_H_
#define INCLUDE_BPAK_UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include <bpak/bpak.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts a binary array to a hex string
 *
 * @param[in] data Data to convert
 * @param[in] data_sz Size of input data in bytes
 * @param[out] buf Output buffer, null terminated
 * @param[in] buf_sz Size of output buffer in bytes, at least 2 * data_sz + 1
 *
 * @return BPAK_OK on success
 */
int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf, size_t buf_sz);

/**
 * Converts a 16 byte UUID to a string
 *
 * @param[in] data UUID
 * @param[out] buf Output buffer, null terminated
 * @param[in] size Size of output buffer in bytes, at least 37
 *
 * @return BPAK_OK on success or -BPAK_SIZE_ERROR if the buffer is too small
 */
int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size);

/**
 * Converts the value of known meta data to a string, unknown meta data
 * results in an empty string
 *
 * @param[in] h BPAK Header
 * @param[in] m Meta data header
 * @param[out] buf Output buffer, null terminated
 * @param[in] size Size of output buffer in bytes
 *
 * @return BPAK_OK on success, -BPAK_SIZE_ERROR and an empty string if the
 *         buffer is too small or the meta data is smaller than its type
 */
int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size);

/**
 * Id of the merkle hash tree part of a part, bpak_id("<part_name>-hash-tree")
 *
 * @param[in] part_name Name of the part
 *
 * @return Id of the hash tree part
 */
bpak_id_t bpak_part_name_to_hash_tree_id(const char *part_name);

/**
 * Id of the merkle hash tree part of a part
 *
 * @param[in] part_id Id of the part
 *
 * @return Id of the hash tree part
 */
bpak_id_t bpak_part_id_to_hash_tree_id(bpak_id_t part_id);

/**
 * Find the part that a merkle hash tree part belongs to
 *
 * @param[in] header BPAK Header
 * @param[in] part_id Id of the hash tree part
 *
 * @return Id of the part or 0 if there is none
 */
bpak_id_t bpak_hash_tree_id_to_part_id(struct bpak_header *header,
                                                  bpak_id_t part_id);
#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_BPAK_UTILS_H_
