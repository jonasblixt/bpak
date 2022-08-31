/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crc.h>
#include <bpak/id.h>

uint32_t bpak_id(const char *str)
{
    return bpak_crc32(0, (const uint8_t *) str, strlen(str));
}

const char *bpak_id_to_string(uint32_t id)
{
    switch(id) {
    case BPAK_ID_BPAK_PACKAGE:
        return "bpak-package";
    case BPAK_ID_BPAK_TRANSPORT:
        return "bpak-transport";
    case BPAK_ID_MERKLE_SALT:
        return "merkle-salt";
    case BPAK_ID_MERKLE_ROOT_HASH:
        return "merkle-root-hash";
    case BPAK_ID_PB_LOAD_ADDR:
        return "pb-load-addr";
    case BPAK_ID_BPAK_VERSION:
        return "bpak-version";
    case BPAK_ID_KEYSTORE_PROVIDER_ID:
        return "keystore-provider-id";
    default:
        return "";
    }
}

