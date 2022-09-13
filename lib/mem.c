/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdlib.h>
#include <bpak/bpak.h>

static bpak_calloc_t _calloc_func = NULL;
static bpak_free_t _free_func = NULL;

int bpak_set_calloc_free(bpak_calloc_t calloc_func, bpak_free_t free_func)
{
    if (calloc_func == NULL || free_func == NULL)
        return -BPAK_FAILED;
    _calloc_func = calloc_func;
    _free_func = free_func;
#ifdef BPAK_BUILD_LZMA
        // TODO: set lzma allocator
#endif
#ifdef BPAK_BUILD_MBEDTLS
        //TODO: set mbedtls allocator
#endif
    return BPAK_OK;
}

void *bpak_calloc(size_t nmemb, size_t size)
{
    if (_calloc_func != NULL) {
        void *ptr = _calloc_func(nmemb, size);
        bpak_printf(2, "<%p> = bpak_calloc(%zu, %zu)\n", ptr, nmemb, size);
        return ptr;
    } else {
        return calloc(nmemb, size);
    }
}

void bpak_free(void *ptr)
{
    if (_free_func != NULL) {
        bpak_printf(2, "bpak_free(%p)\n", ptr);
        _free_func(ptr);
    } else {
        free(ptr);
    }
}
