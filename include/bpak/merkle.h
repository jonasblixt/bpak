/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_MERKLE_H_
#define INCLUDE_BPAK_MERKLE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define MERKLE_BLOCK_SZ 4096
#define MERKLE_MAX_LEVELS 10

typedef unsigned char bpak_merkle_hash_t[32];

struct bpak_merkle_context;
typedef int (*bpak_merkle_io_t) (struct bpak_merkle_context *ctx,
                                    uint64_t offset,
                                    uint8_t *buf,
                                    size_t size,
                                    void *priv);
typedef void (*bpak_merkle_status_t) (struct bpak_merkle_context *ctx);

struct bpak_merkle_level
{
    int level;
    uint64_t size;
    uint64_t byte_counter;
    uint64_t offset;
    uint64_t padded_size;
};

struct bpak_merkle_context
{
    uint8_t buffer[MERKLE_BLOCK_SZ];
    int level;
    int no_of_levels;
    struct bpak_merkle_level current;
    struct bpak_merkle_level previous;
    size_t fs_size;
    size_t hash_tree_size;
    bpak_merkle_hash_t salt;
    bpak_merkle_hash_t hash;
    bpak_merkle_io_t wr;
    bpak_merkle_io_t rd;
    bpak_merkle_status_t status;
    void *priv;
};

size_t bpak_merkle_compute_size(size_t input_data_size, int level, bool pad);

size_t bpak_merkle_get_size(struct bpak_merkle_context *ctx);

bool bpak_merkle_done(struct bpak_merkle_context *ctx);

int bpak_merkle_init(struct bpak_merkle_context *ctx,
                        size_t filesystem_size,
                        bpak_merkle_hash_t salt,
                        bpak_merkle_io_t wr,
                        bpak_merkle_io_t rd,
                        void *priv);

int bpak_merkle_set_status_cb(struct bpak_merkle_context *ctx,
                              bpak_merkle_status_t sts);

int bpak_merkle_process(struct bpak_merkle_context *ctx,
                            uint8_t *input, uint16_t sz);

int bpak_merkle_out(struct bpak_merkle_context *ctx,
                    bpak_merkle_hash_t roothash);

#endif  // INCLUDE_BPAK_MERKLE_H_
