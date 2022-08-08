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

int bpak_bsdiff_hs_init(struct bpak_bsdiff_hs_context *ctx,
                      uint8_t *origin_data,
                      size_t origin_length,
                      uint8_t *new_data,
                      size_t new_length,
                      bpak_io_t write_output,
                      void *user_priv);

int bpak_bsdiff_hs(struct bpak_bsdiff_hs_context *ctx);

int bpak_bsdiff_hs_free(struct bpak_bsdiff_hs_context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_BSDIFF_HS_H_
