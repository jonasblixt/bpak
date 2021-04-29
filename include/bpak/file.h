/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_FILE_H_
#define INCLUDE_BPAK_FILE_H_

#include <bpak/bpak.h>
#include <bpak/io.h>

#ifdef __cplusplus
extern "C" {
#endif

int bpak_io_init_file(struct bpak_io **io_, const char *filename,
                        const char *mode);

const char *bpak_io_filename(struct bpak_io *io);

int bpak_io_replace_file(struct bpak_io *replacee, struct bpak_io *src);

int bpak_io_init_random_file(struct bpak_io **io);
int bpak_io_file_to_fd(struct bpak_io *io);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_FILE_H_
