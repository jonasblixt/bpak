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

struct bpak_bsdiff_context {
    int origin_fd;
    uint8_t *origin_data;
    size_t origin_length;
    int new_fd;
    uint8_t *new_data;
    size_t new_length;
    void *suffix_array;         /*!< int32_t or int64_t entries */
    size_t suffix_array_size;   /*!< Allocated number of entries */
    uint8_t suffix_array_width; /*!< Size of one entry in bytes */
    int64_t scan;
    int64_t len;
    int64_t pos;
    int64_t last_scan;
    int64_t last_pos;
    int64_t last_offset;
    int64_t scsc;
    bpak_io_t write_output;
    off_t output_offset;
    size_t output_pos;
    enum bpak_compression compression;
    void *compressor_priv;
    void *user_priv;
    /* Chunking state, see bpak_bsdiff_set_chunking(). origin_data/new_data
     * above point into the current origin window and target chunk. */
    size_t chunk_size;         /*!< Target chunk size, 0 = no chunking */
    size_t window_margin;      /*!< Origin window margin around a chunk */
    uint8_t *origin_full;      /*!< Complete origin data */
    size_t origin_full_length; /*!< Length of complete origin data */
    uint8_t *new_full;         /*!< Complete target data */
    size_t new_full_length;    /*!< Length of complete target data */
    int64_t origin_base;       /*!< Offset of origin window in origin */
    int64_t new_base;          /*!< Offset of current chunk in target */
    int64_t next_origin_base;  /*!< Origin window offset of next chunk */
    size_t next_origin_length; /*!< Origin window length of next chunk */
    size_t sa_origin_length;   /*!< Window length the suffix array is for */
    int64_t sa_origin_base;    /*!< Window offset the suffix array is for */
    uint64_t *search_tree;     /*!< Prefixes for the first search levels */
    size_t search_tree_size;   /*!< Allocated number of search tree nodes */
    int search_tree_levels;    /*!< Number of levels in the search tree */
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
 * @param[in] output_offset Offset of the output data
 * @param[in] compression Compression of the patch
 * @param[in] user_priv Priv context for i/o callback
 *
 * @return BPAK_OK on success or a negative number
 *
 **/
int bpak_bsdiff_init(struct bpak_bsdiff_context *ctx, uint8_t *origin_data,
                     size_t origin_length, uint8_t *new_data, size_t new_length,
                     bpak_io_t write_output, off_t output_offset,
                     enum bpak_compression compression, void *user_priv);

/**
 * Diff the target in chunks to bound memory usage
 *
 * Without chunking the suffix array covers the entire origin, which needs
 * 4 or 8 bytes per origin byte. With chunking the target is diffed
 * chunk_size bytes at a time against an origin window of
 * chunk_size + 2 * window_margin bytes, so the suffix array only covers
 * the window. The window follows the offset of the latest match, which
 * tracks data that has moved because of insertions or deletions.
 *
 * The generated patch has the same format as an unchunked patch and is
 * applied with bspatch as usual. Matches outside of the window are not
 * found, which may result in a larger patch.
 *
 * Must be called after bpak_bsdiff_init and before bpak_bsdiff.
 *
 * @param[in] ctx The bsdiff context
 * @param[in] chunk_size Target chunk size in bytes, 0 disables chunking
 * @param[in] window_margin Origin bytes to include before and after a chunk
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_bsdiff_set_chunking(struct bpak_bsdiff_context *ctx, size_t chunk_size,
                             size_t window_margin);

/**
 * Perform the diff process
 *
 * @param[in] ctx The bsdiff context
 *
 * @return size of the output patch on success or a negative number
 */
ssize_t bpak_bsdiff(struct bpak_bsdiff_context *ctx);

/**
 * Free the diff context
 *
 * @param[in] ctx The bsdiff context
 */
void bpak_bsdiff_free(struct bpak_bsdiff_context *ctx);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
