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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts a binary array to a hex string
 *
 * @param[in] data Data to convert
 * @param[in] data_sz Size of input data in bytes
 * @param[out] buf Output buffer
 * @param[in] buf_sz Size of output buffer in bytes
 *
 * @return BPAK_OK on success
 */
int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf, size_t buf_sz);

int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size);
int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size);
uint32_t bpak_part_name_to_hash_tree_id(const char *part_name);
uint32_t bpak_part_id_to_hash_tree_id(uint32_t part_id);
uint32_t bpak_hash_tree_id_to_part_id(struct bpak_header *header,
                                                  uint32_t part_id);
#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_BPAK_UTILS_H_
