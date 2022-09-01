/**
 * \file transport.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_TRANSPORT_H_
#define INCLUDE_BPAK_TRANSPORT_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <bpak/bpak.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpak_transport_decode
{
    uint8_t *buffer;
    size_t buffer_length;
    struct bpak_header *patch_header;
    struct bpak_header *origin_header;
    struct bpak_part_header *part;
    bpak_io_t write_output;
    bpak_io_t read_output;
    bpak_io_t read_origin;
    bpak_io_t write_output_header;
    uint32_t decoder_id;
    uint8_t *decode_context_buffer;
    size_t decode_context_buffer_length;
    off_t copy_offset;
    void *user;
};

/**
 * Initalizes the transport decode context for a BPAK package
 *
 * NOTE: It's expected that the user provied correct offsets
 *  for io callbacks. The transport decode layer assumes that
 *  reading/writing at offset zero means where the data starts.
 *
 * @param[in] ctx Pointer to a transport decode context
 * @param[in] buffer Working buffer for decoders
 * @param[in] buffer_length Length of 'buffer' in bytes
 * @param[in] patch_header Input patch BPAK header
 * @param[in] write_output Callback for writing output
 * @param[in] read_output Callback for reading output
 * @param[in] write_output_header Callback for writing the output header
 * @param[in] user User pointer for io callbacks
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_decode_init(struct bpak_transport_decode *ctx,
                               uint8_t *buffer,
                               size_t buffer_length,
                               uint8_t *decode_context_buffer,
                               size_t decode_context_buffer_length,
                               struct bpak_header *patch_header,
                               bpak_io_t write_output,
                               bpak_io_t read_output,
                               bpak_io_t write_output_header,
                               void *user);
/**
 * Provide an origin stream for the decoder. The patch decoder needs
 * an origin stream to produce the target binary. However, de-compressors
 * merkle-tree generator does not need this.
 *
 * @param[in] ctx Pointer to a transport decode context
 * @param[in] origin_header Origin BPAK header
 * @param[in] read_origin Callback for reading origin data
 * @param[in] origin_data_offset Origin data offset
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_decode_set_origin(struct bpak_transport_decode *ctx,
                                     struct bpak_header *origin_header,
                                     bpak_io_t read_origin);
/**
 * Starts the decoding process. Some parts are re-created, for example
 * merkle hash tress, and therefore the input size is zero. In this case the
 * start function will perform the actual decoding and no calls to
 * 'bpak_transport_decode_write_chunk' are needed.
 *
 * Note: This call can take a significant amount of time, for example if
 *  a large hash tree needs to be re-built.
 *
 * @param[in] ctx Pointer to a transport decode context
 * @param[in] part Pointer to the BPAK part that should be processed
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_decode_start(struct bpak_transport_decode *ctx,
                                struct bpak_part_header *part);
/**
 * Write chunked input data to the decoder
 *
 * @param[in] ctx Pointer to a transport decode context
 * @param[in] buffer Pointer to a buffer that holds input data
 * @param[in] length Length of input buffer
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_decode_write_chunk(struct bpak_transport_decode *ctx,
                                      uint8_t *buffer, size_t length);

/**
 * Should be called when no more data should be written to the
 * decoder
 *
 * @param[in] ctx Pointer to a transport decode context
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_decode_finish(struct bpak_transport_decode *ctx);

/**
 * Free's the decoder context
 *
 * @param[in] ctx Pointer to a transport decode context
 *
 */
void bpak_transport_decode_free(struct bpak_transport_decode *ctx);

/**
 * Transport encode package stream 'input_fp' according to metadata in package
 *  and use package stream 'origin_fp' as origin data. The output package
 *  is written to 'output_fp'.
 *
 * NOTE: The transport encode function only accepts input streams where
 *  the bpak header is at the start of the stream and the data at
 *  sizeof(struct bpak_header) offset from start.
 *
 * @param[in] input_fp Input file stream
 * @param[in] input_header BPAK header from input stream
 * @param[in] output_fp Output file stream
 * @param[in] output_header BPAK header from output stream
 * @param[in] origin_fp Origin file stream
 * @param[in] origin_header BPAK header from origin stream
 *
 * @return BPAK_OK on success or a negative number on failure
 */
int bpak_transport_encode(FILE *input_fp, struct bpak_header *input_header,
                          FILE *output_fp, struct bpak_header *output_header,
                          FILE *origin_fp, struct bpak_header *origin_header);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_TRANSPORT_H_
