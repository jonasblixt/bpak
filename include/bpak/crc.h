#ifndef INCLUDE_PBAK_CRC_H_
#define INCLUDE_PBAK_CRC_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t bpak_crc32(uint32_t crc, const uint8_t *buf, uint32_t size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_PBAK_CRC_H_
