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

typedef union
{
    uint8_t raw[16];
    struct
    {
        uint32_t time_low;
        uint16_t time_mid;
        uint16_t time_hi_and_version;
        uint8_t clock_seq_hi_and_res;
        uint8_t clock_seq_low;
        uint8_t node[6];
    } uuid __attribute__((packed));
} bpak_uuid_t;

/**
 * Converts some well known meta data to a textual representation
 *
 * @param[in] h BPAK Header
 * @param[in] m Metadata of interest
 * @param[out] buf Output text buffer
 * @param[in] size Size of output buffer in bytes
 *
 * @return BPAK_OK on success
 */
int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size);
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

/**
 * Convert UUID to string
 *
 * @param[in] data Raw UUID
 * @param[out] buf Output buffer
 * @param[in] size Size of output buffer in bytes
 *
 * @return BPAK_OK on success
 */
int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size);

/**
 * Translate a string to id value
 *
 * @param[in] str Input string
 *
 * @return BPAK ID of \ref str
 */
uint32_t bpak_id(const char *str);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_UTILS_H_
