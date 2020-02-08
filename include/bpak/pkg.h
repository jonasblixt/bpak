#ifndef INCLUDE_BPAK_PKG_H_
#define INCLUDE_BPAK_PKG_H_

#include <bpak/bpak.h>
#include <bpak/io.h>

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


struct bpak_package
{
    struct bpak_io *io;
    struct bpak_header header;
    const char *filename;
};

int bpak_pkg_open(struct bpak_package **pkg_, const char *filename,
                  const char *mode);
int bpak_pkg_close(struct bpak_package *pkg);
int bpak_pkg_compute_hash(struct bpak_package *pkg, char *output, size_t *size);
size_t bpak_pkg_installed_size(struct bpak_package *pkg);
size_t bpak_pkg_size(struct bpak_package *pkg);
struct bpak_header *bpak_pkg_header(struct bpak_package *pkg);
int bpak_pkg_sign(struct bpak_package *pkg, const uint8_t *signature,
                    size_t size);
int bpak_pkg_sign_init(struct bpak_package *pkg, uint32_t key_id,
                            int32_t keystore_id);
int bpak_pkg_read_signature(struct bpak_package *pkg, uint8_t *sig,
                                size_t *sig_size);
#endif  // INCLUDE_BPAK_PKG_H_
