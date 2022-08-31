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

int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf, size_t buf_sz)
{
    uint8_t b;
    int i = data_sz;
    int n = 0;

    for (i = 0; i < data_sz; i++)
    {
        b = data[i];
        b = (b >> 4) & 0x0F;
        buf[n++] = (b > 9)?('a' + (b-10)):('0' + b);

        b = data[i];
        b = b & 0x0F;
        buf[n++] = (b > 9)?('a' + (b-10)):('0' + b);
    }

    buf[n] = 0;

    return BPAK_OK;
}

