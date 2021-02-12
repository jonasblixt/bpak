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

struct bpak_dependency
{
    uint8_t uuid[16];
    char constraint[];
} __attribute__ ((packed));


struct bpak_package
{
    struct bpak_io *io;
    struct bpak_header header;
    const char *filename;
    enum bpak_header_pos header_location;
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

int bpak_pkg_add_transport(struct bpak_package *pkg, uint32_t part_ref,
                                uint32_t encoder_id, uint32_t decoder_id);

int bpak_pkg_transport_encode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us);
int bpak_pkg_transport_decode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us,
                              bool output_header_last);
int bpak_pkg_register_all_algs(void);

/**
 * Writes current header to file
 *
 * @param[in] hdr BPAK Header
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_write_header(struct bpak_package *pkg);

#endif  // INCLUDE_BPAK_PKG_H_
