/**
 * \file bspatch_hs.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_BSPATCH_HS_H_
#define INCLUDE_BPAK_BSPATCH_HS_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <bpak/bspatch.h>
#include <bpak/heatshrink_decoder.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_bspatch_hs_context {
    struct bpak_bspatch_context bspatch_ctx;
    size_t patch_input_length;
    size_t patch_input_position;
    heatshrink_decoder hs;
};

/**
 *  Initialize the BPAK bspatch_hs context
 *
 *  @param[in] hs_ctx        Pointer to the context
 *  @param[in] buffer        Pointer to bspatch state buffer
 *  @param[in] buffer_length Length of `buffer` in bytes, must be a power of two
 *  @param[in] read_origin   Callback for reading origin data
 *  @param[in] write_output  Callback for writing output data
 *  @param[in] user_priv     User context sent to call backs
 *
 *  @return BPAK_OK on success or a negative number
 */
int bpak_bspatch_hs_init(struct bpak_bspatch_hs_context *hs_ctx,
                      uint8_t *buffer,
                      size_t buffer_length,
                      size_t patch_length,
                      bpak_io_t read_origin,
                      bpak_io_t write_output,
                      void *user_priv);

/**
 * Feed bspatch-hs compressed input data
 *
 * @param[in] ctx_hs   Pointer to bspatch context
 * @param[in] buffer   Input buffer
 * @param[in] length   Bytes available in inputbuffer
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_bspatch_hs_write(struct bpak_bspatch_hs_context *hs_ctx,
                                          uint8_t *buffer,
                                          size_t length);

/**
 * Should be called when there is no more input data, to
 * flush the remainder of the de-compression buffer.
 *
 * @param[in] ctx_hs   Pointer to bspatch context
 *
 * @return Output bytes written or a negative number on errors
 */
ssize_t bpak_bspatch_hs_final(struct bpak_bspatch_hs_context *hs_ctx);

/**
 * Free the bspatch_hs context
 *
 * @param[in] hs_ctx bspatch context
 */
void bpak_bspatch_hs_free(struct bpak_bspatch_hs_context *hs_ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_BSPATCH_HS_H_
