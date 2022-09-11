/**
 * \file bsdiff.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BPAK_BSDIFF_H
#define BPAK_BSDIFF_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <bpak/bpak.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_bsdiff_context
{
    int origin_fd;
    uint8_t *origin_data;
    size_t origin_length;
    int new_fd;
    uint8_t *new_data;
    size_t new_length;
    int64_t *suffix_array;
    size_t suffix_array_size;
    int64_t scan;
    int64_t len;
    int64_t pos;
    int64_t last_scan;
    int64_t last_pos;
    int64_t last_offset;
    int64_t scsc;
    char suffix_fn[64];
    bpak_io_t write_output;
    size_t output_pos;
    void *user_priv;
};

/**
 * Initialize a bsdiff context
 *
 * @param[in] ctx The bsdiff context
 * @param[in] origin_data pointer to origin/source data
 * @param[in] origin_length Length of origin data
 * @param[in] new_data New, or target data
 * @param[in] new_length Length of target data
 * @param[in] write_output I/O callback for writing output data
 * @param[in] user_priv Priv context for i/o callback
 *
 * @return BPAK_OK on success or a negative number
 *
 **/
int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      void *user_priv);

/**
 * Perform the diff process
 *
 * @param[in] ctx The bsdiff context
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_bsdiff(struct bpak_bsdiff_context *ctx);

/**
 * Free the diff context
 *
 * @param[in] ctx The bsdiff context
 */
void bpak_bsdiff_free(struct bpak_bsdiff_context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
