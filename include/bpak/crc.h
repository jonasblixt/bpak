#ifndef INCLUDE_PBAK_CRC_H_
#define INCLUDE_PBAK_CRC_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Update a CRC32 (reflected polynomial 0xEDB88320) without the initial and
 * final XOR. bpak_id() is bpak_crc32(0, str, strlen(str)).
 *
 * @param[in] crc CRC of the preceding data, or 0
 * @param[in] buf Input data
 * @param[in] size Size of input data in bytes
 *
 * @return The updated CRC
 */
uint32_t bpak_crc32(uint32_t crc, const uint8_t *buf, uint32_t size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_PBAK_CRC_H_
