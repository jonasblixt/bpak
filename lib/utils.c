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
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/crc.h>
#include <bpak/pkg.h>
#include <bpak/id.h>

#include "uuid.h"

BPAK_EXPORT int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf,
                             size_t buf_sz)
{
    uint8_t b;
    size_t i = data_sz;
    size_t n = 0;

    for (i = 0; i < data_sz; i++) {
        b = data[i];
        b = (b >> 4) & 0x0F;
        buf[n++] = (b > 9) ? ('a' + (b - 10)) : ('0' + b);

        if (n > buf_sz)
            return -1;

        b = data[i];
        b = b & 0x0F;
        buf[n++] = (b > 9) ? ('a' + (b - 10)) : ('0' + b);

        if (n > buf_sz)
            return -1;
    }

    buf[n] = 0;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size)
{
    if (size < 37)
        return -BPAK_SIZE_ERROR;

    uuid_unparse(data, buf);

    return BPAK_OK;
}

BPAK_EXPORT int bpak_meta_to_string(struct bpak_header *h,
                                    struct bpak_meta_header *m, char *buf,
                                    size_t size)
{
    uint32_t *id_ptr = NULL;
    uint8_t *byte_ptr = NULL;

    if (m->id == BPAK_ID_BPAK_KEY_ID) {
        bpak_get_meta(h, m->id, (void **)&id_ptr, NULL);
        snprintf(buf, size, "%x", *id_ptr);
    } else if (m->id == BPAK_ID_BPAK_KEY_STORE) {
        bpak_get_meta(h, m->id, (void **)&id_ptr, NULL);
        snprintf(buf, size, "%x", *id_ptr);
    } else if (m->id == BPAK_ID_BPAK_PACKAGE) {
        bpak_get_meta(h, m->id, (void **)&byte_ptr, NULL);
        bpak_uuid_to_string(byte_ptr, buf, size);
    } else if (m->id == BPAK_ID_BPAK_TRANSPORT) {
        struct bpak_transport_meta *transport_meta =
            (struct bpak_transport_meta *)&(h->metadata[m->offset]);

        snprintf(buf,
                 size,
                 "Encode: %8.8x, Decode: %8.8x",
                 transport_meta->alg_id_encode,
                 transport_meta->alg_id_decode);
    } else if (m->id == BPAK_ID_MERKLE_SALT) {
        bpak_get_meta(h, m->id, (void **)&byte_ptr, NULL);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    } else if (m->id == BPAK_ID_MERKLE_ROOT_HASH) {
        bpak_get_meta(h, m->id, (void **)&byte_ptr, NULL);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    } else if (m->id == BPAK_ID_PB_LOAD_ADDR) {
        uint64_t *entry_addr = (uint64_t *)&(h->metadata[m->offset]);
        snprintf(buf, size, "Entry: %p", (void *)*entry_addr);
    } else if (m->id == BPAK_ID_BPAK_VERSION) {
        bpak_get_meta(h, m->id, (void **)&byte_ptr, NULL);

        if (m->size > size)
            return -BPAK_SIZE_ERROR;

        memcpy(buf, byte_ptr, m->size);
    } else if (m->id == BPAK_ID_KEYSTORE_PROVIDER_ID) {
        bpak_get_meta(h, m->id, (void **)&id_ptr, NULL);
        snprintf(buf, size, "0x%x", *id_ptr);
    } else {
        if (size)
            *buf = 0;
    }

    return BPAK_OK;
}

BPAK_EXPORT uint32_t bpak_part_name_to_hash_tree_id(const char *part_name)
{
    return bpak_part_id_to_hash_tree_id(bpak_id(part_name));
}

BPAK_EXPORT uint32_t bpak_part_id_to_hash_tree_id(uint32_t part_id)
{
    return bpak_crc32(part_id, (uint8_t *)"-hash-tree", 10);
}

BPAK_EXPORT uint32_t bpak_hash_tree_id_to_part_id(struct bpak_header *header,
                                                  uint32_t part_id)
{
    bpak_foreach_part (header, part) {
        if (bpak_crc32(part->id, (uint8_t *)"-hash-tree", 10) == part_id) {
            return part->id;
        }
    }

    return 0;
}
