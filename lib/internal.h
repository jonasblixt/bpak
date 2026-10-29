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
#include <stdio.h>
#include <bpak/bpak.h>

/** Iterate over the parts in use, they end at the first empty slot */
#define bpak_foreach_used_part(_hdr, _var)                                     \
    for (struct bpak_part_header *_var = (_hdr)->parts;                        \
         _var != &((_hdr)->parts[BPAK_MAX_PARTS]) && _var->id != 0;            \
         _var++)

/** Size of a part in the decoded package, with its padding */
static inline uint64_t
bpak_part_decoded_size(const struct bpak_part_header *part)
{
    return part->size + part->pad_bytes;
}

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

/**
 * Offset of the data of 'part' in a stream that has the data of the first
 * part at 'data_offset', a stream without the header for example.
 */
off_t bpak_part_data_offset(struct bpak_header *h,
                            struct bpak_part_header *part, off_t data_offset);

/**
 * bpak_io_t callbacks that read and write 'length' bytes at 'offset' of the
 * FILE * in 'user'.
 *
 * @return The number of bytes, a short read or write is checked by the
 *         caller, or -BPAK_SEEK_ERROR
 */
ssize_t bpak_file_read(off_t offset, uint8_t *buffer, size_t length,
                       void *user);
ssize_t bpak_file_write(off_t offset, uint8_t *buffer, size_t length,
                        void *user);

/** Consumer of the data of bpak_file_feed(), returns BPAK_OK or an error */
typedef int (*bpak_consume_t)(void *priv, uint8_t *buffer, size_t length);

/**
 * Read 'length' bytes from the current position of 'fp' in chunks and pass
 * them to 'consume'.
 *
 * @return BPAK_OK, -BPAK_READ_ERROR on a short read or the error of
 *         'consume'
 */
int bpak_file_feed(FILE *fp, uint64_t length, bpak_consume_t consume,
                   void *priv);

/**
 * Copy 'length' bytes from the current position of 'in_fp' to 'out_fp'.
 *
 * @return BPAK_OK, -BPAK_READ_ERROR on a short read or -BPAK_WRITE_ERROR
 */
int bpak_file_copy(FILE *in_fp, FILE *out_fp, uint64_t length);

#endif // BPAK_LIB_INTERNAL_H
