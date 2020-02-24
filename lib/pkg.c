#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/alg.h>
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

    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

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

    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

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

int bpak_pkg_add_transport(struct bpak_package *pkg, uint32_t part_ref,
                                uint32_t encoder_id, uint32_t decoder_id)
{
    int rc;
    struct bpak_transport_meta *meta = NULL;

    rc = bpak_add_meta(&pkg->header, bpak_id("bpak-transport"), part_ref,
                                    (void **) &meta, sizeof(*meta));

    if (rc != BPAK_OK)
        return rc;

    meta->alg_id_encode = encoder_id;
    meta->alg_id_decode = decoder_id;

    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_io_write(pkg->io, &pkg->header, sizeof(pkg->header));

    if (rc != sizeof(pkg->header))
        return -BPAK_FAILED;

    return BPAK_OK;
}

static int transport_process(struct bpak_transport_meta *tm,
                                 struct bpak_header *h,
                                 uint32_t part_ref_id,
                                 struct bpak_io *io,
                                 struct bpak_io *origin,
                                 uint8_t *state_buffer,
                                 size_t size,
                                 bool decode_flag,
                                 int rate_limit_us)
{
    int rc;
    struct bpak_alg_instance ins;
    struct bpak_part_header *p = NULL;
    struct bpak_io *tmp;
    struct bpak_alg *alg = NULL;
    uint64_t bytes_to_copy = 0;
    size_t chunk_sz = 0;
    size_t read_bytes = 0;
    size_t written_bytes = 0;
    uint32_t alg_id = 0;

    rc = bpak_get_part(h, part_ref_id, &p);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    bpak_printf(2, "Encoding part %x (%p)\n", part_ref_id, p);

    if (decode_flag)
        alg_id = tm->alg_id_decode;
    else
        alg_id = tm->alg_id_encode;

    bpak_printf(2, "Using alg: %x\n", alg_id);

    rc = bpak_alg_get(alg_id, &alg);

    bpak_printf(2, "Initializing alg: %x (%p)\n", alg_id, alg);

    if (rc != BPAK_OK || !alg)
    {
        bpak_printf(0, "Error: Unknown algorithm: %8.8x\n", alg_id);
        return rc;
    }

    bpak_printf(1, "Processing part %8.8x using '%s' [%8.8x]\n", part_ref_id,
                                alg->name, alg_id);

    /* Already processed for transport ?*/
    if ((p->flags & BPAK_FLAG_TRANSPORT) && (!decode_flag))
        return BPAK_OK;

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    rc = bpak_io_init_random_file(&tmp);

    if (rc != BPAK_OK)
        goto err_close_io_out;

    bpak_printf(2, "Created temporary file: %s\n", bpak_io_filename(tmp));

    /* Copy everyting up until the part we are interested in */

    bpak_io_write(tmp, h, sizeof(*h));

    bpak_foreach_part(h, part)
    {
        if (part->id == p->id)
            break;
        if (!part->id)
            continue;

        bpak_io_seek(io, bpak_part_offset(h, part), BPAK_IO_SEEK_SET);

        bytes_to_copy = bpak_part_size(part);

        while (bytes_to_copy)
        {
            chunk_sz = (bytes_to_copy > size)?size:bytes_to_copy;
            bpak_io_read(io, state_buffer, chunk_sz);
            bpak_io_write(tmp, state_buffer, chunk_sz);
            bytes_to_copy -= chunk_sz;
        }
    }

    bpak_printf(1, "Initializing alg, input size %li bytes\n", bpak_part_size(p));

    bpak_io_seek(io, bpak_part_offset(h, p), BPAK_IO_SEEK_SET);

    rc = bpak_alg_init(&ins, alg_id, p, h, state_buffer, size,
                            io, tmp, origin);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not initialize algorithm %8.8x\n", alg_id);
        return -BPAK_FAILED;
    }

    while (!bpak_alg_done(&ins))
    {
        rc = bpak_alg_process(&ins);

        if (rc != BPAK_OK)
        {
            bpak_printf(0, "Error: processing failed\n");
            break;
        }

        usleep(rate_limit_us);
    }

    if (rc != BPAK_OK)
        goto err_close_io_out;

    bpak_alg_free(&ins);

    bpak_printf(1, "Done processing, output size %li bytes\n", ins.output_size);

    /* Position input stream at the end of the part in intereset */
    rc = bpak_io_seek(io, bpak_part_offset(h, p) + bpak_part_size(p),
                                        BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not seek 1\n");
        bpak_printf(0, "    part:        %8.8x\n", p->id);
        bpak_printf(0, "    part offset: %li\n", bpak_part_offset(h, p));
        bpak_printf(0, "    part size:   %li\n", bpak_part_size(p));
        goto err_close_io_out;
    }

    /* Update part header to indicate that the part has been coded */
    if (decode_flag)
    {
        p->flags &= ~BPAK_FLAG_TRANSPORT;
        p->transport_size = 0;
    }
    else
    {
        p->transport_size = bpak_alg_output_size(&ins);
        p->flags |= BPAK_FLAG_TRANSPORT;
    }

    bpak_io_seek(tmp, 0, BPAK_IO_SEEK_SET);
    bpak_io_write(tmp, h, sizeof(*h));

    /* Position output stream at the end of the processed part*/
    rc = bpak_io_seek(tmp, bpak_part_offset(h, p) + bpak_part_size(p),
                    BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error: Could not seek\n");
        bpak_printf(0, "    offset: %li\n", bpak_part_offset(h, p));
        bpak_printf(0, "    size:   %li\n", bpak_part_size(p));
        goto err_close_io_out;
    }

    while(true)
    {
        read_bytes = bpak_io_read(io, state_buffer, size);

        if (read_bytes == 0)
            break;

        written_bytes = bpak_io_write(tmp, state_buffer, read_bytes);

        if (read_bytes != written_bytes)
        {
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }
    }

    rc = bpak_io_replace_file(io, tmp);

err_close_io_out:
    bpak_io_close(tmp);
    return rc;
}

int bpak_pkg_transport_encode(struct bpak_package *pkg,
                              struct bpak_package *origin,
                              int rate_limit_us)
{
    int rc;
    uint8_t *state_buffer = malloc(1024*1024);
    memset(state_buffer, 0, 1024*1024);

    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_transport_meta *tm = NULL;

    bpak_printf(2, "Transport encode begin, pkg = %p, origin = %p, " \
                "rate_limit_us = %li\n", pkg, origin, rate_limit_us);

    bpak_foreach_meta(&pkg->header, mh)
    {
        if (!mh->id)
            break;

        if (mh->id == bpak_id("bpak-transport"))
        {
            bpak_get_meta(h, mh->id, (void **) &tm);
            struct bpak_io *origin_io = NULL;

            if (origin)
                origin_io = origin->io;

            rc = transport_process(tm, h, mh->part_id_ref,
                    pkg->io, origin_io, state_buffer, 1024*1024, false,
                    rate_limit_us);

            if (rc != BPAK_OK)
                break;

        }
    }

    free(state_buffer);
    return rc;
}

int bpak_pkg_transport_decode(struct bpak_package *pkg,
                              struct bpak_package *origin,
                              int rate_limit_us)
{
    int rc;
    struct bpak_header *h = bpak_pkg_header(pkg);
    uint8_t *state_buffer = malloc(1024*1024);
    memset(state_buffer, 0, 1024*1024);

    struct bpak_transport_meta *tm = NULL;

    bpak_foreach_meta(h, mh)
    {
        if (!mh->id)
            break;

        if (mh->id == bpak_id("bpak-transport"))
        {
            bpak_get_meta(h, mh->id, (void **) &tm);
            struct bpak_io *origin_io = NULL;

            if (origin)
                origin_io = origin->io;

            rc = transport_process(tm, h, mh->part_id_ref,
                    pkg->io, origin_io, state_buffer, 1024*1024, true,
                    rate_limit_us);

            if (rc != BPAK_OK)
                break;

        }
    }

    free(state_buffer);
    return rc;
}

int bpak_pkg_register_all_algs(void)
{
#ifdef BUILD_BPAK_CODECS
    bpak_alg_remove_register();
    bpak_alg_bsdiff_register();
    bpak_alg_bspatch_register();
    bpak_alg_heatshrink_register();
    bpak_alg_merkle_register();
#endif
}
