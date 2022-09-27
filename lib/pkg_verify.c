/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/verify.h>
#include <bpak/keystore.h>

static ssize_t verify_payload_read(off_t offset, uint8_t *buf, size_t size,
                                void *user)
{
    FILE *fp = (FILE *) user;

    if (fseek(fp, offset, SEEK_SET) != 0)
        return -BPAK_SEEK_ERROR;

    size_t read_bytes = fread(buf, 1, size, fp);

    if (read_bytes != size)
        return -BPAK_READ_ERROR;

    return read_bytes;
}

BPAK_EXPORT int bpak_pkg_verify(struct bpak_package *pkg, const char *key_filename)
{
    int rc;
    uint8_t hash_output[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash_output);
    struct bpak_key *key = NULL;
    bool header_verified = false;

    rc = bpak_verify_compute_header_hash(&pkg->header, hash_output, &hash_size);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_crypto_load_public_key(key_filename, &key);

    if (rc != BPAK_OK)
        goto err_out;

    rc = bpak_crypto_verify(pkg->header.signature,
                            pkg->header.signature_sz,
                            hash_output, hash_size,
                            pkg->header.hash_kind,
                            key, &header_verified);

    if (rc != BPAK_OK)
        goto err_free_key_out;
    if (header_verified == false) {
        rc = -BPAK_VERIFY_FAIL;
        goto err_free_key_out;
    }

    rc = bpak_verify_payload(&pkg->header, 
                             verify_payload_read,
                             sizeof(struct bpak_header),
                             pkg->fp);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: payload verification failed\n");
        goto err_free_key_out;
    }

err_free_key_out:
    bpak_free(key);
err_out:
    return rc;
}
