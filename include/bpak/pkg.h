/**
 * \file pkg.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_PKG_H_
#define INCLUDE_BPAK_PKG_H_

#include <bpak/bpak.h>
#include <bpak/io.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \public
 *
 * BPAK dependancy operators
 */
enum
{
    BPAK_DEP_EQ,        /* == Equal */
    BPAK_DEP_GT,        /* >  Greater than */
    BPAK_DEP_GTE,       /* >= Greater than or equal */
};

/**
 * Dependency meta data
 *
 **/
struct bpak_dependency
{
    uint8_t uuid[16];   /*!< Package UUID to depend on */
    char constraint[];  /*!< Constrain expression for example >= 1.0.0 */
} __attribute__ ((packed));

/**
 * BPAK Package
 *
 */
struct bpak_package
{
    struct bpak_io *io;                   /*!< I/O Stream  for package */
    struct bpak_header header;            /*!< BPAK Header */
    const char *filename;                 /*!< Filename */
    enum bpak_header_pos header_location; /*!< Header location */
};

/**
 * Open a package for reading or writing
 *
 * @param[in] pkg Package pointer
 * @param[in] filename Filename
 * @param[in] mode File mode
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_open(struct bpak_package **pkg_, const char *filename,
                  const char *mode);

/**
 * Close a package
 *
 * @param[in] pkg Package pointer
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_close(struct bpak_package *pkg);

/**
 * Computes the package hash
 *
 * @param[in] pkg Package pointer
 * @param[out] out Output hash
 * @param[in, out] size Input size of \ref output buffer and result of computation size is stored here as well
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_compute_hash(struct bpak_package *pkg, char *output, size_t *size);

/**
 * Computes the package size after transport decoding
 *
 * @param[in] pkg Package pointer
 *
 * @return Size in bytes
 */
size_t bpak_pkg_installed_size(struct bpak_package *pkg);

/**
 * Computes the package size before transport decoding
 *
 * @param[in] pkg Package pointer
 *
 * @return Size in bytes
 */
size_t bpak_pkg_size(struct bpak_package *pkg);

/**
 * Get the package header pointer
 *
 * @param[in] pkg Package pointer
 *
 * @return Pointer to the header
 */
struct bpak_header *bpak_pkg_header(struct bpak_package *pkg);

/**
 * Populate the signature data array
 *
 * @param[in] pkg Package pointer
 * @param[in] signature DER encoded signature
 * @param[in] size Size of \ref signature in bytes
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_sign(struct bpak_package *pkg, const uint8_t *signature,
                    size_t size);

/**
 * Add transport metadata
 *
 * @param[in] pkg Package pointer
 * @param[in] part_ref Part reference, id of part we want to add meta data to
 * @param[in] encoder_id Which encoder to use for transport encoding
 * @param[in] decoder_id Which decoder to use for transport decoding
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_add_transport(struct bpak_package *pkg, uint32_t part_ref,
                                uint32_t encoder_id, uint32_t decoder_id);
/**
 * Transport encode package
 *
 * @param[in] input BPAK Package input stream
 * @param[in] output BPAK Package output, the result
 * @param[in] origin BPAK Package origin data
 * @param[in] rate_limit_us Rate limit the operation by sleeping \ref rate_limit_us between every encoding step
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_transport_encode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us);

/**
 * Transport decode package
 *
 * @param[in] input BPAK Package input stream
 * @param[in] output BPAK Package output, the result
 * @param[in] origin BPAK Package origin data
 * @param[in] rate_limit_us Rate limit the operation by sleeping \ref rate_limit_us between every encoding step
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_transport_decode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us,
                              bool output_header_last);
/**
 * Register all built in algorithms. This must be called before using
 *  any of the transport encoding or decoding functions.
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_register_all_algs(void);

/**
 * Writes current header to file
 *
 * @param[in] hdr BPAK Header
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_write_header(struct bpak_package *pkg);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // INCLUDE_BPAK_PKG_H_
