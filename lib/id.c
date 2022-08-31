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
