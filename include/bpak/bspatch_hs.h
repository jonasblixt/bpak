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

int bpak_bspatch_hs_init(struct bpak_bspatch_hs_context *hs_ctx,
                      uint8_t *buffer,
                      size_t buffer_length,
                      size_t patch_length,
                      bpak_io_t read_origin,
                      bpak_io_t write_output,
                      void *user_priv);

int bpak_bspatch_hs_write(struct bpak_bspatch_hs_context *hs_ctx,
                                          uint8_t *buffer,
                                          size_t length);
ssize_t bpak_bspatch_hs_final(struct bpak_bspatch_hs_context *hs_ctx);
int bpak_bspatch_hs_free(struct bpak_bspatch_hs_context *hs_ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_BSPATCH_HS_H_
