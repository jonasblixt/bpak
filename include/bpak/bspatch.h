/**
 * \file bspatch.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef BPAK_BSPATCH_H
#define BPAK_BSPATCH_H

#include <stdint.h>
#include <stddef.h>
#include <bpak/bpak.h>

#define BPAK_BSPATCH_CTRL_BUFFER_LENGTH 24

#ifdef __cplusplus
extern "C" {
#endif

enum bpak_bspatch_state
{
    BPAK_PATCH_STATE_FILL_CTRL_BUF,
    BPAK_PATCH_STATE_READ_CTRL,
    BPAK_PATCH_STATE_APPLY_DIFF,
    BPAK_PATCH_STATE_APPLY_EXTRA,
    BPAK_PATCH_STATE_FINISH,
    BPAK_PATCH_STATE_ERROR,
};

struct bpak_bspatch_context {
    off_t origin_position;          /*!< Current position in origin data */
    off_t origin_offset;            /*!< Origin stream offset */
    off_t output_position;          /*!< Current position in output data */
    off_t output_offset;            /*!< Output stream offset */
    enum bpak_bspatch_state state;  /*!< Current state of bspatch */
    uint8_t *patch_buffer;          /*!< Chunk of patch data input */
    size_t patch_buffer_length;     /*!< Length of patch buffer */
    uint8_t *input_buffer;
    size_t input_buffer_length;
    size_t input_length;
    size_t input_position;
    bpak_io_t read_origin;          /*!< Callback for reading origin data */
    bpak_io_t write_output;         /*!< Callback for writing output data */
    uint8_t ctrl_buf[BPAK_BSPATCH_CTRL_BUFFER_LENGTH];
                                    /*!< Hold the current control header */
    uint8_t ctrl_buf_count;         /*!< Fill status of control buffer */
    int64_t diff_count;             /*!< Current patch block: amount of diff bytes */
    int64_t extra_count;            /*!< Current patch block: extra bytes */
    int64_t adjust;                 /*!< Current patch block: Origin offset adjustment */
    void *decompressor_priv;
    enum bpak_compression compression;
    void *user_priv;
};

/**
 *  Initialize the BPAK bspatch context
 *
 *  @param[in] ctx           Pointer to the context
 *  @param[in] buffer_length Size of bspatch internal buffers in bytes
 *  @param[in] read_origin   Callback for reading origin data
 *  @param[in] write_output  Callback for writing output data
 *  @param[in] user_priv     User context sent to call backs
 *
 *  @return BPAK_OK on success or a negative number
 */
int bpak_bspatch_init(struct bpak_bspatch_context *ctx,
                      size_t buffer_length,
                      size_t input_length,
                      bpak_io_t read_origin,
                      off_t origin_offset,
                      bpak_io_t write_output,
                      off_t output_offset,
                      enum bpak_compression compression,
                      void *user_priv);

/**
 * Feed bspatch with input data
 *
 * @param[in] ctx      Pointer to bspatch context
 * @param[in] buffer   Input buffer
 * @param[in] length   Bytes available in inputbuffer
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_bspatch_write(struct bpak_bspatch_context *ctx,
                          uint8_t *buffer,
                          size_t length);

/**
 * Call bpak_bsptach_final when there is no more input.
 *
 * @param[in] ctx Pointer to bspatch context
 *
 * @return  the output patched size or a negative number on error
 */
ssize_t bpak_bspatch_final(struct bpak_bspatch_context *ctx);


/**
 * Free the bspatch context
 *
 * @param[in] ctx bspatch context
 *
 */
void bpak_bspatch_free(struct bpak_bspatch_context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
