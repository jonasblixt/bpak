#ifndef INCLUDE_BPAK_PKG_H_
#define INCLUDE_BPAK_PKG_H_

#include <bpak/bpak.h>

enum
{
    BPAK_DEP_EQ,        /* == Equal */
    BPAK_DEP_GT,        /* >  Greater than */
    BPAK_DEP_GTE,       /* >= Greater than or equal */
};

struct bpak_version
{
    uint8_t major;
    uint8_t minor;
    uint16_t patch;
} __attribute__ ((packed));

struct bpak_dependency
{
    uint8_t uuid[16];
    struct bpak_version version;
    uint8_t kind;
} __attribute__ ((packed));

#endif  // INCLUDE_BPAK_PKG_H_
