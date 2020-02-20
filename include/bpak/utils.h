#ifndef INCLUDE_BPAK_UTILS_H_
#define INCLUDE_BPAK_UTILS_H_

#include <stdint.h>
#include <stddef.h>

typedef union
{
    uint8_t raw[16];
    struct
    {
        uint32_t time_low;
        uint16_t time_mid;
        uint16_t time_hi_and_version;
        uint8_t clock_seq_hi_and_res;
        uint8_t clock_seq_low;
        uint8_t node[6];
    } uuid __attribute__((packed));
} bpak_uuid_t;

int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size);

int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf, size_t buf_sz);

int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size);

/* Translate a string to id value */
uint32_t bpak_id(const char *str);

#endif  // INCLUDE_BPAK_UTILS_H_
