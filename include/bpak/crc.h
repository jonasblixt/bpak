#ifndef INCLUDE_PBAK_CRC_H_
#define INCLUDE_PBAK_CRC_H_

#include <stdint.h>

uint32_t bpak_crc32(uint32_t crc, const uint8_t *buf, uint32_t size);

#endif  // INCLUDE_PBAK_CRC_H_
