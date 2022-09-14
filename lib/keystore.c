/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <bpak/bpak.h>
#include <bpak/keystore.h>

int bpak_keystore_get(struct bpak_keystore *ks, uint32_t id,
                        struct bpak_key **k)
{
    *k = NULL;

    if (!ks->verified)
        return -BPAK_FAILED;

    for (unsigned int i = 0; i < ks->no_of_keys; i++) {
        if (ks->keys[i]->id == id) {
            *k = ks->keys[i];
            return BPAK_OK;
        }
    }

    return -BPAK_KEY_NOT_FOUND;
}
