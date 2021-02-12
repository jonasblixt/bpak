#include <stdio.h>
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

    if (!mode)
        return -BPAK_FAILED;

    bpak_printf(1, "Opening BPAK file %s\n", filename);

    *pkg_ = malloc(sizeof(struct bpak_package));
    struct bpak_package *pkg = *pkg_;

    if (!*pkg_)
        return -BPAK_FAILED;

    memset(pkg, 0, sizeof(*pkg));

    rc = bpak_io_init_file(&pkg->io, filename, mode);

    if (rc != BPAK_OK)
        goto err_free_pkg;

    pkg->header_location = BPAK_HEADER_POS_FIRST;
    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        goto err_close_io;

    size_t read_bytes = bpak_io_read(pkg->io, &pkg->header,
                                        sizeof(pkg->header));
    if (read_bytes != sizeof(pkg->header))
    {
        rc = -BPAK_FAILED;
        goto skip_header;
    }

    rc = bpak_valid_header(&pkg->header);

    if (rc != BPAK_OK) {
        /* Check if the header is at the end */
        rc = bpak_io_seek(pkg->io, 4096, BPAK_IO_SEEK_END);

        if (rc != BPAK_OK) {
            goto skip_header;
        }

        read_bytes = bpak_io_read(pkg->io, &pkg->header,
                                            sizeof(pkg->header));
        if (read_bytes != sizeof(pkg->header))
        {
            rc = -BPAK_FAILED;
            goto skip_header;
        }

        rc = bpak_valid_header(&pkg->header);

        if (rc != BPAK_OK)
            goto skip_header;

        pkg->header_location = BPAK_HEADER_POS_LAST;
    }

skip_header:
    rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
        goto err_close_io;

    return BPAK_OK;

err_close_io:
    bpak_io_close(pkg->io);
err_free_pkg:
    free(pkg);
    *pkg_ = NULL;
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
    uint8_t signature[512];
    uint16_t signature_sz;

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

    char hash_buffer[512];

    if (pkg->header_location == BPAK_HEADER_POS_FIRST) {
        bpak_io_seek(pkg->io, sizeof(pkg->header), BPAK_IO_SEEK_SET);
    } else {
        bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);
    }

    bpak_foreach_part(&pkg->header, p) {
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

    memset(pkg->header.payload_hash, 0, sizeof(pkg->header.payload_hash));
    memcpy(signature, pkg->header.signature, sizeof(signature));
    signature_sz = pkg->header.signature_sz;

    memset(pkg->header.signature, 0, sizeof(pkg->header.signature));
    pkg->header.signature_sz = 0;

    if (pkg->header.hash_kind == BPAK_HASH_SHA256)
        mbedtls_sha256_finish_ret(&sha256, pkg->header.payload_hash);
    else
        mbedtls_sha512_finish_ret(&sha512, pkg->header.payload_hash);

    switch (pkg->header.hash_kind)
    {
        case BPAK_HASH_SHA256:
            mbedtls_sha256_init(&sha256);
            mbedtls_sha256_starts_ret(&sha256, 0);
        break;
        case BPAK_HASH_SHA384:
            mbedtls_sha512_init(&sha512);
            mbedtls_sha512_starts_ret(&sha512, 1);
        break;
        case BPAK_HASH_SHA512:
            mbedtls_sha512_init(&sha512);
            mbedtls_sha512_starts_ret(&sha512, 0);
        break;
        default:
            return -BPAK_NOT_SUPPORTED;
    }

    if (pkg->header.hash_kind == BPAK_HASH_SHA256)
        rc = mbedtls_sha256_update_ret(&sha256, (char *) &pkg->header,
                                        sizeof(pkg->header));
    else
        rc = mbedtls_sha512_update_ret(&sha512, (char *) &pkg->header,
                                        sizeof(pkg->header));

    if (pkg->header.hash_kind == BPAK_HASH_SHA256)
        mbedtls_sha256_finish_ret(&sha256, output);
    else
        mbedtls_sha512_finish_ret(&sha512, output);

    memcpy(pkg->header.signature, signature, sizeof(signature));
    pkg->header.signature_sz = signature_sz;
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

int bpak_pkg_write_header(struct bpak_package *pkg)
{
    int rc;

    if (pkg->header_location == BPAK_HEADER_POS_FIRST) {
        rc = bpak_io_seek(pkg->io, 0, BPAK_IO_SEEK_SET);
    } else {
        rc = bpak_io_seek(pkg->io, 4096, BPAK_IO_SEEK_END);
    }

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Could not seek\n", __func__);
        return rc;
    }

    rc = bpak_io_write(pkg->io, &pkg->header, sizeof(pkg->header));

    if (rc != sizeof(pkg->header)) {
        bpak_printf(0, "%s: Write failed\n", __func__);
        return -BPAK_FAILED;
    }

    return BPAK_OK;
}

int bpak_pkg_sign(struct bpak_package *pkg, const uint8_t *signature,
                    size_t size)
{
    int rc;
    uint8_t *signature_ptr = NULL;

    memset(pkg->header.signature, 0, sizeof(pkg->header.signature));
    memcpy(pkg->header.signature, signature, size);
    pkg->header.signature_sz = size;

    return bpak_pkg_write_header(pkg);
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

    return bpak_pkg_write_header(pkg);
}

static int transport_copy(struct bpak_header *hdr, uint32_t id,
                          struct bpak_package *input,
                          struct bpak_package *output)
{
    int rc;
    struct bpak_io *input_io = input->io;
    struct bpak_io *output_io = output->io;
    struct bpak_part_header *p = NULL;
    uint64_t part_offset = 0;

    rc = bpak_get_part(hdr, id, &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error could not get part with ref %x\n", id);
        return rc;
    }

    part_offset = bpak_part_offset(hdr, p);

    rc = bpak_io_seek(input_io, part_offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Could not seek input stream\n", __func__);
    }

    uint8_t buf[1024];
    uint64_t bytes_to_copy = bpak_part_size(p);
    uint64_t chunk = 0;

    while (bytes_to_copy) {
        chunk = (bytes_to_copy > sizeof(buf))?sizeof(buf):bytes_to_copy;
        uint64_t read_bytes = bpak_io_read(input_io, buf, chunk);

        if (read_bytes != chunk) {
            bpak_printf(0, "Error: Could not read chunk");
            rc = -BPAK_FAILED;
            goto err_out;
        }

        uint64_t written_bytes = bpak_io_write(output_io, buf, chunk);

        if (written_bytes != read_bytes) {
            bpak_printf(0, "Error: Could not write chunk");
            rc = -BPAK_FAILED;
            goto err_out;
        }

        bytes_to_copy -= chunk;
    }

err_out:
    return rc;
}

static int transport_process(struct bpak_transport_meta *tm,
                                 uint32_t part_ref_id,
                                 struct bpak_package *input,
                                 struct bpak_package *output,
                                 struct bpak_package *origin,
                                 uint8_t *state_buffer,
                                 size_t size,
                                 bool decode_flag,
                                 bool output_header_last,
                                 int rate_limit_us)
{
    int rc = 0;
    struct bpak_alg_instance ins;
    struct bpak_part_header *p = NULL;
    struct bpak_part_header *op = NULL;
    struct bpak_io *input_io = input->io;
    struct bpak_io *output_io = output->io;
    struct bpak_io *origin_io = NULL;
    struct bpak_alg *alg = NULL;
    uint64_t bytes_to_copy = 0;
    size_t chunk_sz = 0;
    size_t read_bytes = 0;
    size_t written_bytes = 0;
    uint32_t alg_id = 0;
    struct bpak_header *input_header = bpak_pkg_header(input);
    struct bpak_header *output_header = bpak_pkg_header(output);

    if (origin) {
        origin_io = origin->io;
    }

    rc = bpak_get_part(input_header, part_ref_id, &p);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    rc = bpak_get_part(output_header, part_ref_id, &op);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    bpak_printf(2, "Encoding part %x (%p)\n", part_ref_id, p);

    if (decode_flag) {
        alg_id = tm->alg_id_decode;
    } else {
        alg_id = tm->alg_id_encode;
    }

    bpak_printf(2, "Using alg: %x\n", alg_id);

    rc = bpak_alg_get(alg_id, &alg);

    bpak_printf(2, "Initializing alg: %x (%p)\n", alg_id, alg);

    if (rc != BPAK_OK || !alg) {
        bpak_printf(0, "Error: Unknown algorithm: %8.8x\n", alg_id);
        return rc;
    }

    bpak_printf(1, "Processing part %8.8x using '%s' [%8.8x]\n", part_ref_id,
                                alg->name, alg_id);

    /* Already processed for transport ?*/
    if ((op->flags & BPAK_FLAG_TRANSPORT) && (!decode_flag))
        return BPAK_OK;

    if (output_header_last == false) {
        bpak_io_seek(output_io, 0, BPAK_IO_SEEK_SET);
        bpak_io_write(output_io, output_header, sizeof(*output_header));
    }

    bpak_printf(1, "Initializing alg, input size %li bytes\n", bpak_part_size(p));

    rc = bpak_io_seek(origin_io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek origin stream", __func__);
        return rc;
    }

    rc = bpak_io_seek(input_io,
                 bpak_part_offset(input_header, p),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek input stream", __func__);
        return rc;
    }

    rc = bpak_io_seek(output_io,
                 bpak_part_offset(output_header, p),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return rc;
    }

    rc = bpak_alg_init(&ins, alg_id, p, input_header, state_buffer, size,
               input_io, output_io, origin_io,
               origin->header_location,
               output_header_last?BPAK_HEADER_POS_LAST:BPAK_HEADER_POS_FIRST);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not initialize algorithm %8.8x\n", alg_id);
        return -BPAK_FAILED;
    }

    while (!bpak_alg_done(&ins)) {
        rc = bpak_alg_process(&ins);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: processing failed\n");
            break;
        }

        usleep(rate_limit_us);
    }

    if (rc != BPAK_OK)
        goto err_out;

    bpak_alg_free(&ins);

    bpak_printf(1, "Done processing, output size %li bytes\n", ins.output_size);

    /* Update part header to indicate that the part has been coded */
    if (decode_flag) {
        op->flags &= ~BPAK_FLAG_TRANSPORT;
        op->transport_size = 0;
    } else {
        op->transport_size = bpak_alg_output_size(&ins);
        op->flags |= BPAK_FLAG_TRANSPORT;
    }

    /* Position output stream at the end of the processed part*/
    rc = bpak_io_seek(output_io, bpak_part_offset(output_header, op) +
                                 bpak_part_size(op),
                                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not seek\n", __func__);
        bpak_printf(0, "    offset: %li\n", bpak_part_offset(output_header, op));
        bpak_printf(0, "    size:   %li\n", bpak_part_size(op));
        goto err_out;
    }

err_out:
    return rc;
}

#define DECODE_STATE_BUF_SZ (1024*1024)

int bpak_pkg_transport_encode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us)
{
    int rc = BPAK_OK;
    uint8_t *state_buffer = malloc(DECODE_STATE_BUF_SZ);
    memset(state_buffer, 0, DECODE_STATE_BUF_SZ);

    struct bpak_header *h = bpak_pkg_header(input);
    struct bpak_header *oh = bpak_pkg_header(output);
    struct bpak_transport_meta *tm = NULL;
    struct bpak_part_header *ph = NULL;
    memcpy(oh, h, sizeof(*h));

    bpak_printf(2, "Transport encode begin, input = %p, origin = %p, " \
                "rate_limit_us = %li\n", input, origin, rate_limit_us);

    bpak_foreach_part(&input->header, ph) {
        if (ph->id == 0)
            break;
/*
        bpak_printf(0, "In: %lu, Out: %lu, Origin: %lu\n",
                        bpak_io_tell(input->io),
                        bpak_io_tell(output->io),
                        bpak_io_tell(origin->io));
*/
        if (bpak_get_meta_with_ref(&input->header,
                                   bpak_id("bpak-transport"),
                                   ph->id,
                                   (void **) &tm) == BPAK_OK) {
            bpak_printf(2, "Transport encoding part: %x\n", ph->id);

            rc = transport_process(tm, ph->id,
                                   input, output, origin,
                                   state_buffer, DECODE_STATE_BUF_SZ,
                                   false, false,
                                   rate_limit_us);

            if (rc != BPAK_OK)
                break;
        } else { /* No transport coding, copy data */
            bpak_printf(2, "Copying part: %x\n", ph->id);

            rc = transport_copy(&input->header, ph->id, input, output);

            if (rc != BPAK_OK)
                break;
        }
    }

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Failed\n", __func__);
        goto err_out;
    }

    rc = bpak_io_seek(output->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not seek\n");
        goto err_out;
    }

    ssize_t written = bpak_io_write(output->io, oh, sizeof(*oh));

    if (written != sizeof(*oh)) {
        bpak_printf(0, "Error: could not write header");
        rc = -1;
    }
err_out:
    free(state_buffer);
    return rc;
}

int bpak_pkg_transport_decode(struct bpak_package *input,
                              struct bpak_package *output,
                              struct bpak_package *origin,
                              int rate_limit_us,
                              bool output_header_last)
{
    int rc = BPAK_OK;
    struct bpak_header *h = bpak_pkg_header(input);
    struct bpak_header *oh = bpak_pkg_header(output);
    struct bpak_part_header *ph = NULL;
    uint8_t *state_buffer = malloc(DECODE_STATE_BUF_SZ);
    memset(state_buffer, 0, DECODE_STATE_BUF_SZ);
    memcpy(oh, h, sizeof(*h));
    struct bpak_transport_meta *tm = NULL;

    bpak_foreach_part(&input->header, ph) {
        if (ph->id == 0)
            break;

        if (bpak_get_meta_with_ref(&input->header,
                                   bpak_id("bpak-transport"),
                                   ph->id,
                                   (void **) &tm) == BPAK_OK) {
            bpak_printf(2, "Transport encoding part: %x\n", ph->id);

            rc = transport_process(tm, ph->id,
                                   input, output, origin,
                                   state_buffer, DECODE_STATE_BUF_SZ,
                                   true, output_header_last,
                                   rate_limit_us);

            if (rc != BPAK_OK)
                break;
        } else { /* No transport coding, copy data */
            bpak_printf(2, "Copying part: %x\n", ph->id);

            rc = transport_copy(&input->header, ph->id, input, output);

            if (rc != BPAK_OK)
                break;
        }
    }
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Failed\n", __func__);
        goto err_out;
    }

    if (output_header_last) {
       rc = bpak_io_seek(output->io, 4096, BPAK_IO_SEEK_END);
    } else {
       rc = bpak_io_seek(output->io, 0, BPAK_IO_SEEK_SET);
    }

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not seek\n");
        goto err_out;
    }

    ssize_t written = bpak_io_write(output->io, oh, sizeof(*oh));

    if (written != sizeof(*oh)) {
        bpak_printf(0, "Error: could not write header");
        rc = -1;
    }

err_out:
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

    return BPAK_OK;
}
