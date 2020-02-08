#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/file.h>
#include <bpak/utils.h>

#include "sha256.h"
#include "sha512.h"

int bpak_pkg_open(struct bpak_package **pkg_, const char *filename,
                  const char *mode)
{
    int rc;
    *pkg_ = malloc(sizeof(struct bpak_package));
    struct bpak_package *pkg = *pkg_;

    if (!*pkg_)
        return -BPAK_FAILED;

    memset(pkg, 0, sizeof(*pkg));

    rc = bpak_io_init_file(&pkg->io, filename, mode);

    if (rc != BPAK_OK)
        return rc;

    size_t read_bytes = bpak_io_read(pkg->io, &pkg->header,
                                        sizeof(pkg->header));
    if (read_bytes != sizeof(pkg->header))
    {
        rc = -BPAK_FAILED;
        goto err_close_io;
    }

    rc = bpak_valid_header(&pkg->header);

    if (rc != BPAK_OK)
        goto err_close_io;

    return BPAK_OK;

err_close_io:
    bpak_io_close(pkg->io);
    return rc;
}

int bpak_pkg_close(struct bpak_package *pkg)
{
    bpak_io_close(pkg->io);
    free(pkg);
    return BPAK_OK;
}

int bpak_pkg_compute_hash(struct bpak_package *pkg, char *output, size_t *size)
{
    int rc;
    mbedtls_sha256_context sha256;
    mbedtls_sha512_context sha512;

    switch (pkg->header.hash_kind)
    {
        case BPAK_HASH_SHA256:
            if (*size < 32)
                return -BPAK_FAILED;
            *size = 32;
            mbedtls_sha256_init(&sha256);
            mbedtls_sha256_starts_ret(&sha256, 0);
        break;
        case BPAK_HASH_SHA384:
            if (*size < 48)
                return -BPAK_FAILED;
            *size = 48;
            mbedtls_sha512_init(&sha512);
            mbedtls_sha512_starts_ret(&sha512, 1);
        break;
        case BPAK_HASH_SHA512:
            if (*size < 64)
                return -BPAK_FAILED;
            *size = 64;
            mbedtls_sha512_init(&sha512);
            mbedtls_sha512_starts_ret(&sha512, 0);
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    /* Zero out signature if it exists */
    bpak_foreach_meta(&pkg->header, m)
    {
        if (m->id == bpak_id("bpak-signature"))
        {
            uint8_t *ptr = &(pkg->header.metadata[m->offset]);
            memset(ptr, 0, m->size);
            memset(m, 0, sizeof(*m));
        }
    }

    if (pkg->header.hash_kind == BPAK_HASH_SHA256)
        rc = mbedtls_sha256_update_ret(&sha256, (char *) &pkg->header,
                                        sizeof(pkg->header));
    else
        rc = mbedtls_sha512_update_ret(&sha512, (char *) &pkg->header,
                                        sizeof(pkg->header));

    char hash_buffer[512];
    char hash_output[64];

    bpak_io_seek(pkg->io, sizeof(pkg->header), BPAK_IO_SEEK_SET);

    bpak_foreach_part(&pkg->header, p)
    {
        size_t bytes_to_read = bpak_part_size(p);
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
        {
            bpak_io_seek(pkg->io, bpak_part_size(p), BPAK_IO_SEEK_FWD);
            continue;
        }

        do
        {
            chunk = (bytes_to_read > sizeof(hash_buffer))?
                        sizeof(hash_buffer):bytes_to_read;

            bpak_io_read(pkg->io, hash_buffer, chunk);

            if (pkg->header.hash_kind == BPAK_HASH_SHA256)
                rc = mbedtls_sha256_update_ret(&sha256, hash_buffer, chunk);
            else
                rc = mbedtls_sha512_update_ret(&sha512, hash_buffer, chunk);

            bytes_to_read -= chunk;
        } while (bytes_to_read);
    }

    if (pkg->header.hash_kind == BPAK_HASH_SHA256)
        mbedtls_sha256_finish_ret(&sha256, output);
    else
        mbedtls_sha512_finish_ret(&sha512, output);

    return rc;
}

size_t bpak_pkg_installed_size(struct bpak_package *pkg)
{
    size_t installed_size = 0;

    bpak_foreach_part(&pkg->header, p)
    {
        installed_size += p->size + p->pad_bytes;
    }

    return installed_size;
}

size_t bpak_pkg_size(struct bpak_package *pkg)
{
    size_t transport_size = 0;

    bpak_foreach_part(&pkg->header, p)
    {
        if (p->flags & BPAK_FLAG_TRANSPORT)
            transport_size += p->transport_size;
        else
            transport_size += p->size;
    }

    transport_size += sizeof(struct bpak_header);

    return transport_size;
}

struct bpak_header *bpak_pkg_header(struct bpak_package *pkg)
{
    return &pkg->header;
}

int bpak_pkg_sign_init(struct bpak_package *pkg, uint32_t key_id,
                            int32_t keystore_id)
{
    int rc;
    uint32_t *key_id_ptr = NULL;
    uint32_t *key_store_ptr = NULL;

    rc = bpak_get_meta(&pkg->header, bpak_id("bpak-key-id"),
                        (void **) &key_id_ptr);

    if (rc != BPAK_OK)
    {
        rc = bpak_add_meta(&pkg->header, bpak_id("bpak-key-id"),
                        0, (void **) &key_id_ptr, sizeof(uint32_t));
    }

    if (rc != BPAK_OK)
    {
        return rc;
    }

    rc = bpak_get_meta(&pkg->header, bpak_id("bpak-key-store"),
                            (void **) &key_store_ptr);

    if (rc != BPAK_OK)
    {
        rc = bpak_add_meta(&pkg->header, bpak_id("bpak-key-store"), 0,
                            (void **) &key_store_ptr, sizeof(uint32_t));
    }

    if (rc != BPAK_OK)
    {
        return rc;
    }

    *key_id_ptr = key_id;
    *key_store_ptr = keystore_id;
    return rc;
}

int bpak_pkg_sign(struct bpak_package *pkg, const uint8_t *signature,
                    size_t size)
{
    int rc;
    uint8_t *signature_ptr = NULL;


    /* Remove any existing signatures */
    bpak_foreach_meta(&pkg->header, m)
    {
        if (!m->id)
            break;

        if (m->id == bpak_id("bpak-signature"))
        {
            uint8_t *ptr = &(pkg->header.metadata[m->offset]);
            memset(ptr, 0, m->size);
            memset(m, 0, sizeof(*m));
            break;
        }
    }

    rc = bpak_add_meta(&pkg->header, bpak_id("bpak-signature"), 0,
                        (void **) &signature_ptr, size);

    if (rc != BPAK_OK)
        return rc;

    memcpy(signature_ptr, signature, size);

    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_io_write(pkg->io, &pkg->header, sizeof(pkg->header));

    if (rc != sizeof(pkg->header))
        return -BPAK_FAILED;

    return BPAK_OK;
}

int bpak_pkg_read_signature(struct bpak_package *pkg, uint8_t *sig,
                                size_t *sig_size)
{

    bpak_foreach_meta(&pkg->header, m)
    {
        if (!m->id)
            break;

        if (m->id == bpak_id("bpak-signature"))
        {
            uint8_t *ptr = &(pkg->header.metadata[m->offset]);
            if (m->size > *sig_size)
                return -BPAK_FAILED;
            *sig_size = m->size;
            memcpy(sig, ptr, m->size);
            return BPAK_OK;
        }
    }

    return -BPAK_FAILED;
}
