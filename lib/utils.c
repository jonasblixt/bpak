/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/crc.h>
#include <bpak/pkg.h>
#include <bpak/id.h>
#include <bpak/merkle.h>

#include "internal.h"

static const char hex[] = "0123456789abcdef";

BPAK_EXPORT int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf,
                             size_t buf_sz)
{
    /* Two characters per byte and a null terminator */
    if (buf_sz < (data_sz * 2 + 1))
        return -1;

    for (size_t i = 0; i < data_sz; i++) {
        buf[i * 2] = hex[(data[i] >> 4) & 0x0F];
        buf[i * 2 + 1] = hex[data[i] & 0x0F];
    }

    buf[data_sz * 2] = 0;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size)
{
    if (size < 37)
        return -BPAK_SIZE_ERROR;

    char *p = buf;

    /* The 16 bytes in order as 8-4-4-4-12 lower case hex digits */
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            *p++ = '-';

        *p++ = hex[(data[i] >> 4) & 0x0F];
        *p++ = hex[data[i] & 0x0F];
    }

    *p = 0;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_meta_to_string(struct bpak_header *h,
                                    struct bpak_meta_header *m, char *buf,
                                    size_t size)
{
    uint8_t *byte_ptr = bpak_get_meta_ptr(h, m, uint8_t);
    bpak_id_t id_value;
    uint64_t u64_value;
    struct bpak_transport_meta transport_meta;
    int n = 0;
    int rc = BPAK_OK;

    if (size == 0)
        return -BPAK_SIZE_ERROR;

    *buf = 0;

    /* Values that are too small for their type are an error. The values are
     * copied, they may not be aligned for their type. */
    switch (m->id) {
    case BPAK_ID_BPAK_KEY_ID:
    case BPAK_ID_BPAK_KEY_STORE:
        if (m->size < sizeof(id_value))
            return -BPAK_SIZE_ERROR;

        memcpy(&id_value, byte_ptr, sizeof(id_value));
        n = snprintf(buf, size, "%" PRIx32, id_value);
        break;
    case BPAK_ID_KEYSTORE_PROVIDER_ID:
        if (m->size < sizeof(id_value))
            return -BPAK_SIZE_ERROR;

        memcpy(&id_value, byte_ptr, sizeof(id_value));
        n = snprintf(buf, size, "0x%" PRIx32, id_value);
        break;
    case BPAK_ID_BPAK_PACKAGE:
        if (m->size < 16)
            return -BPAK_SIZE_ERROR;

        rc = bpak_uuid_to_string(byte_ptr, buf, size);
        break;
    case BPAK_ID_BPAK_TRANSPORT:
        if (m->size < sizeof(transport_meta))
            return -BPAK_SIZE_ERROR;

        memcpy(&transport_meta, byte_ptr, sizeof(transport_meta));
        n = snprintf(buf,
                     size,
                     "Encode: %8.8" PRIx32 ", Decode: %8.8" PRIx32,
                     transport_meta.alg_id_encode,
                     transport_meta.alg_id_decode);
        break;
    case BPAK_ID_MERKLE_SALT:
    case BPAK_ID_MERKLE_ROOT_HASH:
        if (m->size < BPAK_MERKLE_HASH_BYTES)
            return -BPAK_SIZE_ERROR;

        rc =
            bpak_bin2hex(byte_ptr, BPAK_MERKLE_HASH_BYTES, buf, size) == BPAK_OK
                ? BPAK_OK
                : -BPAK_SIZE_ERROR;
        break;
    case BPAK_ID_PB_LOAD_ADDR:
        if (m->size < sizeof(u64_value))
            return -BPAK_SIZE_ERROR;

        memcpy(&u64_value, byte_ptr, sizeof(u64_value));
        n = snprintf(buf, size, "Entry: 0x%08" PRIX64, u64_value);
        break;
    case BPAK_ID_BPAK_VERSION: {
        /* Stored with a NUL, which a package may leave out */
        size_t length = m->size;

        if (length > 0 && byte_ptr[length - 1] == 0)
            length--;

        if (length >= size)
            return -BPAK_SIZE_ERROR;

        memcpy(buf, byte_ptr, length);
        buf[length] = 0;
    } break;
    default:
        break;
    }

    /* snprintf truncated the string */
    if (n < 0 || (size_t)n >= size)
        rc = -BPAK_SIZE_ERROR;

    if (rc != BPAK_OK)
        *buf = 0;

    return rc;
}

BPAK_EXPORT bpak_id_t bpak_part_name_to_hash_tree_id(const char *part_name)
{
    return bpak_part_id_to_hash_tree_id(bpak_id(part_name));
}

BPAK_EXPORT uint32_t bpak_part_id_to_hash_tree_id(bpak_id_t part_id)
{
    return bpak_crc32(part_id, (uint8_t *)"-hash-tree", 10);
}

BPAK_EXPORT bpak_id_t bpak_hash_tree_id_to_part_id(struct bpak_header *header,
                                                  bpak_id_t part_id)
{
    bpak_foreach_used_part (header, part) {
        if (bpak_part_id_to_hash_tree_id(part->id) == part_id) {
            return part->id;
        }
    }

    return 0;
}
