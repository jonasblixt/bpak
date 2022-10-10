/**
 * \file pkg.h
 *
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef INCLUDE_BPAK_PKG_H_
#define INCLUDE_BPAK_PKG_H_

#include <stdio.h>
#include <bpak/bpak.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BPAK Package
 *
 */
struct bpak_package {
    FILE *fp;                  /*!< I/O Stream  for package */
    struct bpak_header header; /*!< BPAK Header */
    const char *filename;      /*!< Filename */
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
int bpak_pkg_open(struct bpak_package *pkg, const char *filename,
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
 * Computes the package header hash. This function also updates the payload
 * hash in the header
 *
 * @param[in] pkg Package pointer
 * @param[out] out Optional header output hash
 * @param[in, out] size Optional input size of \ref output buffer and result of
 * computation size is stored here as well
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_update_hash(struct bpak_package *pkg, char *output, size_t *size);

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
int bpak_pkg_write_raw_signature(struct bpak_package *pkg,
                                 const uint8_t *signature, size_t size);

/**
 * Sign the package
 *
 * @param[in] pkg Package pointer
 * @param[in] key_filename Full path of key to be used for signing
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_sign(struct bpak_package *pkg, const char *key_filename);

/**
 * Verify the package
 *
 * @param[in] pkg Package pointer
 * @param[in] key_filename Full path of key to be used for verify operation
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_verify(struct bpak_package *pkg, const char *key_filename);

/**
 * Compute sha256 hash of part data
 *
 * @param[in] pkg Package pointer
 * @param[out] hash_buffer Output buffer
 * @param[in] hash_buffer_length length of hash buffer
 * @param[in] part_id Id of part to be hashed
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_part_sha256(struct bpak_package *pkg,
                         uint8_t *hash_buffer,
                         size_t hash_buffer_length,
                         uint32_t part_id);

/**
 * Transport encode package
 *
 * @param[in] input BPAK Package input stream
 * @param[in] output BPAK Package output, the result
 * @param[in] origin BPAK Package origin data
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_transport_encode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin);

/**
 * Transport decode package
 *
 * @param[in] input BPAK Package input stream
 * @param[in] output BPAK Package output, the result
 * @param[in] origin BPAK Package origin data
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_transport_decode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin);

/**
 * Writes current header to file
 *
 * @param[in] hdr BPAK Header
 *
 * @return BPAK_OK on success
 */
int bpak_pkg_write_header(struct bpak_package *pkg);

/**
 * Add a file part to a package
 *
 * @param[in] pkg Pointer to a bpak package
 * @param[in] filename Full path to the file that should be added to the archive
 * @param[in] part_name Name of part to be created
 * @param[in] flags Optional flags for part meta data header
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_pkg_add_file(struct bpak_package *pkg, const char *filename,
                      const char *part_name, uint8_t flags);

/**
 * Add a file part to a package and create a separate part with a merkle
 * hash tree.
 *
 * The hash tree part name will be bpak_id('part_name'-hash-tree')
 *
 * @param[in] pkg Pointer to a bpak package
 * @param[in] filename Full path to the file that should be added to the archive
 * @param[in] part_name Name of part to be created
 * @param[in] flags Optional flags for part meta data header
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_pkg_add_file_with_merkle_tree(struct bpak_package *pkg,
                                       const char *filename,
                                       const char *part_name, uint8_t flags);

/**
 * Add a crypto key to the archive. This can add both PEM and DER encoded
 * keys
 *
 * @param[in] pkg Pointer to a bpak package
 * @param[in] filename Full path to the file that should be added to the archive
 * @param[in] part_name Name of part to be created
 * @param[in] flags Optional flags for part meta data header
 *
 * @return BPAK_OK on success or a negative number
 */
int bpak_pkg_add_key(struct bpak_package *pkg, const char *filename,
                     const char *part_name, uint8_t flags);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_BPAK_PKG_H_
