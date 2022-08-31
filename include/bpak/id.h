/**
 * \file utils.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef INCLUDE_BPAK_ID_H_
#define INCLUDE_BPAK_ID_H_

#include <stdint.h>
#include <stddef.h>

/* Meta data ID's */
#define BPAK_ID_BPAK_TRANSPORT (0x2d44bbfb)
#define BPAK_ID_MERKLE_SALT (0x7c9b2f93)
#define BPAK_ID_MERKLE_ROOT_HASH (0xe68fc9be)
#define BPAK_ID_KEYSTORE_PROVIDER_ID (0xfb367d9a)
#define BPAK_ID_BPAK_DEPENDENCY (0x0ba87349)
#define BPAK_ID_BPAK_VERSION (0x9a5bab69)
#define BPAK_ID_PB_LOAD_ADDR (0xd1e64a4b)
#define BPAK_ID_BPAK_PACKAGE (0xfb2f1f3f)

/* Algorithm ID's */
#define BPAK_ID_BSDIFF (0x9f7aacf9)
#define BPAK_ID_BSPATCH (0xb5964388)
#define BPAK_ID_MERKLE_GENERATE (0xb5bcc58f)
#define BPAK_ID_REMOVE_DATA (0x57004cd0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Translate a string to id value
 *
 * @param[in] str Input string
 *
 * @return BPAK ID of \ref str
 */
uint32_t bpak_id(const char *str);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_UTILS_H_
