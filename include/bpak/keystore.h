#ifndef INCLUDE_BPAK_KEYSTORE_H_
#define INCLUDE_BPAK_KEYSTORE_H_

#include <bpak/bpak.h>
#include <bpak/key.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*bpak_check_header_t)(struct bpak_header *header, void *user);

struct bpak_keystore {
    uint32_t id;
    uint8_t no_of_keys;
    bool verified;
    struct bpak_key *keys[];
};

int bpak_keystore_get(struct bpak_keystore *ks, uint32_t id,
                      struct bpak_key **k);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_BPAK_KEYSTORE_H_
