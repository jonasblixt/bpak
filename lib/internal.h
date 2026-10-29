/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2026 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/* Internal functions of the library, they are not exported */

#ifndef BPAK_LIB_INTERNAL_H
#define BPAK_LIB_INTERNAL_H

#include <stdint.h>
#include <bpak/bpak.h>

/**
 * Get a pointer to the value of the meta data 'id' of the part
 * 'part_id_ref'.
 *
 * @return BPAK_OK, the error of bpak_get_meta() when the meta data is
 *         missing or -BPAK_SIZE_ERROR when it is smaller than 'min_size' or
 *         larger than 'max_size' bytes
 */
int bpak_get_meta_value(struct bpak_header *hdr, bpak_id_t id,
                        bpak_id_t part_id_ref, size_t min_size, size_t max_size,
                        uint8_t **value);

/**
 * Compare the package uuids, the 'bpak-package' meta data, of two packages.
 *
 * @return BPAK_OK when they are the same, an error of bpak_get_meta_value()
 *         or -BPAK_PACKAGE_UUID_MISMATCH
 */
int bpak_same_package_uuid(struct bpak_header *a, struct bpak_header *b);

#endif // BPAK_LIB_INTERNAL_H
