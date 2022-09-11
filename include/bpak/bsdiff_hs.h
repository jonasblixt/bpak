/**
 * \file bsdiff_hs.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_BSDIFF_HS_H_
#define INCLUDE_BPAK_BSDIFF_HS_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <bpak/bpak.h>
#include <bpak/bsdiff.h>
#include <bpak/heatshrink_encoder.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_bsdiff_hs_context {
    struct bpak_bsdiff_context bsdiff_ctx;
    heatshrink_encoder hse;
    size_t output_pos;
    void *user_priv;
    bpak_io_t write_output;
};

/**
 * Initialize a bsdiff heatshrink context
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
int bpak_bsdiff_hs_init(struct bpak_bsdiff_hs_context *ctx,
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
int bpak_bsdiff_hs(struct bpak_bsdiff_hs_context *ctx);

/**
 * Free the diff context
 *
 * @param[in] ctx The bsdiff context
 */
void bpak_bsdiff_hs_free(struct bpak_bsdiff_hs_context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_BSDIFF_HS_H_
