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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpak/bpak.h>
#include <bpak/crc.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include <bpak/merkle.h>
#include <bpak/bsdiff.h>
#include <bpak/transport.h>

static int transport_copy(struct bpak_header *input_hdr,
                          struct bpak_header *output_hdr, uint32_t id,
                          FILE *input_fp, FILE *output_fp)
{
    int rc;
    struct bpak_part_header *p = NULL;
    uint64_t part_offset = 0;

    rc = bpak_get_part(input_hdr, id, &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error could not get part with ref %x\n", id);
        return rc;
    }

    part_offset = bpak_part_offset(input_hdr, p);

    rc = fseek(input_fp, part_offset, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Could not seek input stream\n", __func__);
        return -BPAK_SEEK_ERROR;
    }

    rc = fseek(output_fp, bpak_part_offset(output_hdr, p), SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return -BPAK_SEEK_ERROR;
    }

    uint8_t buf[1024];
    uint64_t bytes_to_copy = bpak_part_size(p);
    uint64_t chunk = 0;

    while (bytes_to_copy) {
        chunk = (bytes_to_copy > sizeof(buf)) ? sizeof(buf) : bytes_to_copy;
        uint64_t read_bytes = fread(buf, 1, chunk, input_fp);

        if (read_bytes != chunk) {
            bpak_printf(0, "Error: Could not read chunk");
            rc = -BPAK_READ_ERROR;
            goto err_out;
        }

        uint64_t written_bytes = fwrite(buf, 1, chunk, output_fp);

        if (written_bytes != read_bytes) {
            bpak_printf(0, "Error: Could not write chunk");
            rc = -BPAK_WRITE_ERROR;
            goto err_out;
        }

        bytes_to_copy -= chunk;
    }

err_out:
    return rc;
}

struct bsdiff_private {
    int fd;
};

/* Write's the compressed output of bsdiff */
static ssize_t bsdiff_write_output(off_t offset, uint8_t *buffer, size_t length,
                                   void *user_priv)
{
    struct bsdiff_private *priv = (struct bsdiff_private *)user_priv;

    if (lseek(priv->fd, offset, SEEK_SET) == -1) {
        bpak_printf(0, "Error: bsdiff_write_output seek\n");
        return -BPAK_SEEK_ERROR;
    }

    ssize_t bytes_written = write(priv->fd, buffer, length);

    if (bytes_written < 0) {
        return bytes_written;
    }

    if (bytes_written != (ssize_t)length) {
        bpak_printf(0, "Error: bsdiff_write_output write\n");
        return -BPAK_WRITE_ERROR;
    }

    return bytes_written;
}

static ssize_t transport_bsdiff(FILE *target, off_t target_offset,
                                size_t target_length, FILE *origin,
                                off_t origin_offset, size_t origin_length,
                                FILE *output, off_t output_offset,
                                enum bpak_compression compression)
{
    ssize_t rc;
    struct bsdiff_private priv;
    struct bpak_bsdiff_context bsdiff;
    uint8_t *origin_data = NULL;
    uint8_t *origin_data_mmap = NULL;
    uint8_t *target_data = NULL;
    uint8_t *target_data_mmap = NULL;
    int target_fd = fileno(target);
    int origin_fd = fileno(origin);

    memset(&priv, 0, sizeof(priv));
    priv.fd = fileno(output);

    /* Map the entrire file because mmap's offset must be page aligned and
     * we need to handle non page aligned offsets */
    if (fseek(target, 0, SEEK_END) != 0)
        return -BPAK_SEEK_ERROR;

    long target_file_sz = ftell(target);

    if (target_file_sz == -1)
        return -BPAK_SEEK_ERROR;

    target_data_mmap =
        mmap(NULL, target_file_sz, PROT_READ, MAP_SHARED, target_fd, 0);

    if (((intptr_t)target_data_mmap) == -1) {
        bpak_printf(0,
                    "Error: Could not mmap target data (%s)\n",
                    strerror(errno));
        return -BPAK_FAILED;
    }

    /* Calculate pointer to where the needed data starts */
    target_data = target_data_mmap + target_offset;

    if (fseek(origin, 0, SEEK_END) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_munmap_target;
    }

    long origin_file_sz = ftell(origin);

    if (origin_file_sz == -1) {
        rc = -BPAK_SEEK_ERROR;
        goto err_munmap_target;
    }

    origin_data_mmap =
        mmap(NULL, origin_file_sz, PROT_READ, MAP_SHARED, origin_fd, 0);

    if (((intptr_t)origin_data_mmap) == -1) {
        bpak_printf(0,
                    "Error: Could not mmap origin data (%s)\n",
                    strerror(errno));
        rc = -BPAK_FAILED;
        goto err_munmap_target;
    }

    /* Calculate pointer to where the needed data starts */
    origin_data = origin_data_mmap + origin_offset;

    rc = bpak_bsdiff_init(&bsdiff,
                          origin_data,
                          origin_length,
                          target_data,
                          target_length,
                          bsdiff_write_output,
                          output_offset,
                          compression,
                          &priv);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: bpak_bsdiff_init failed (%i)\n", rc);
        goto err_munmap_origin;
    }

    rc = bpak_bsdiff(&bsdiff);

    if (rc < 0) {
        bpak_printf(0, "Error: bpak_bsdiff failed (%i)\n", rc);
        goto err_bsdiff_free;
    }

    bpak_printf(1, "bsdiff completed, output size = %zu\n", rc);

err_bsdiff_free:
    bpak_bsdiff_free(&bsdiff);
err_munmap_origin:
    munmap(origin_data_mmap, origin_file_sz);
err_munmap_target:
    munmap(target_data_mmap, target_file_sz);
    return rc;
}

static int
transport_encode_part(struct bpak_transport_meta *tm, uint32_t part_ref_id,
                      FILE *input_fp, struct bpak_header *input_header,
                      FILE *output_fp, struct bpak_header *output_header,
                      FILE *origin_fp, struct bpak_header *origin_header)
{
    int rc = 0;
    struct bpak_part_header *input_part = NULL;
    struct bpak_part_header *output_part = NULL;
    struct bpak_part_header *origin_part = NULL;
    uint32_t alg_id = 0;
    ssize_t output_size = -1;

    rc = bpak_get_part(input_header, part_ref_id, &input_part);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    rc = bpak_get_part(output_header, part_ref_id, &output_part);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    if (origin_header != NULL) {
        rc = bpak_get_part(origin_header, part_ref_id, &origin_part);

        if (rc != BPAK_OK) {
            bpak_printf(0,
                        "Error could not get part with ref %x\n",
                        part_ref_id);
            return rc;
        }
    }

    alg_id = tm->alg_id_encode;
    bpak_printf(2,
                "Encoding part 0x%x using encoder 0x%x\n",
                part_ref_id,
                alg_id);

    /* Already processed for transport ?*/
    if ((output_part->flags & BPAK_FLAG_TRANSPORT))
        return BPAK_OK;

    bpak_printf(1,
                "Initializing alg, input size %li bytes\n",
                bpak_part_size(input_part));

    if (origin_header != NULL && origin_fp != NULL) {
        rc = fseek(origin_fp,
                   bpak_part_offset(origin_header, origin_part),
                   SEEK_SET);

        if (rc != 0) {
            bpak_printf(0, "%s: Error, could not seek origin stream", __func__);
            return rc;
        }
    }

    rc = fseek(input_fp, bpak_part_offset(input_header, input_part), SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek input stream", __func__);
        return rc;
    }

    rc = fseek(output_fp,
               bpak_part_offset(output_header, output_part),
               SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return rc;
    }

    switch (alg_id) {
    case BPAK_ID_BSDIFF: /* heatshrink compressor */
    case BPAK_ID_BSDIFF_NO_COMP:
    case BPAK_ID_BSDIFF_LZMA: {
        if ((origin_header == NULL) || (origin_fp == NULL)) {
            bpak_printf(0, "Error: Need an origin stream for diff operation\n");
            rc = -BPAK_PATCH_READ_ORIGIN_ERROR;
            goto err_out;
        }

        enum bpak_compression compression = BPAK_COMPRESSION_NONE;

        if (alg_id == BPAK_ID_BSDIFF)
            compression = BPAK_COMPRESSION_HS;
        else if (alg_id == BPAK_ID_BSDIFF_NO_COMP)
            compression = BPAK_COMPRESSION_NONE;
        else if (alg_id == BPAK_ID_BSDIFF_LZMA)
            compression = BPAK_COMPRESSION_LZMA;

        output_size =
            transport_bsdiff(input_fp,
                             bpak_part_offset(input_header, input_part),
                             bpak_part_size(input_part),
                             origin_fp,
                             bpak_part_offset(origin_header, origin_part),
                             bpak_part_size(origin_part),
                             output_fp,
                             bpak_part_offset(output_header, output_part),
                             compression);
    } break;
    case BPAK_ID_REMOVE_DATA:
        /* No data is produced for this part */
        output_size = 0;
        break;
    default:
        bpak_printf(0, "Error, unknown alg 0x%x\n", alg_id);
        rc = -1;
        goto err_out;
    }

    if (output_size < 0) {
        bpak_printf(0, "Error: processing of part failed (%i)\n", output_size);
        rc = output_size;
        goto err_out;
    }

    bpak_printf(1, "Done processing, output size %li bytes\n", output_size);

    /* Update part header to indicate that the part has been coded */
    output_part->transport_size = output_size;
    output_part->flags |= BPAK_FLAG_TRANSPORT;

err_out:
    return rc;
}

int bpak_transport_encode(FILE *input_fp, struct bpak_header *input_header,
                          FILE *output_fp, struct bpak_header *output_header,
                          FILE *origin_fp, struct bpak_header *origin_header)
{
    int rc = BPAK_OK;
    struct bpak_meta_header *meta = NULL;
    struct bpak_transport_meta *tm = NULL;
    ssize_t written;

    if ((origin_fp != NULL) && (origin_header != NULL)) {
        uint8_t *origin_package_uuid;
        uint8_t *patch_package_uuid;

        /* Origin and input package should have the same package-uuid */
        rc = bpak_get_meta(origin_header,
                           BPAK_ID_BPAK_PACKAGE,
                           0,
                           &meta);

        origin_package_uuid = bpak_get_meta_ptr(origin_header, meta, uint8_t);

        if (rc != BPAK_OK)
            return rc;

        rc = bpak_get_meta(input_header,
                           BPAK_ID_BPAK_PACKAGE,
                           0,
                           &meta);

        patch_package_uuid = bpak_get_meta_ptr(input_header, meta, uint8_t);

        if (rc != BPAK_OK)
            return rc;

        if (memcmp(origin_package_uuid, patch_package_uuid, 16) != 0)
            return -BPAK_PACKAGE_UUID_MISMATCH;
    }

    /* Initialize output header by copying the input header */
    memcpy(output_header, input_header, sizeof(*input_header));

    bpak_foreach_part (input_header, ph) {
        if (ph->id == 0)
            break;

        if (bpak_get_meta(input_header,
                          BPAK_ID_BPAK_TRANSPORT,
                          ph->id,
                          &meta) == BPAK_OK) {
            tm = bpak_get_meta_ptr(input_header, meta, struct bpak_transport_meta);
            bpak_printf(2, "Transport encoding part: %x\n", ph->id);

            rc = transport_encode_part(tm,
                                       ph->id,
                                       input_fp,
                                       input_header,
                                       output_fp,
                                       output_header,
                                       origin_fp,
                                       origin_header);

            if (rc != BPAK_OK)
                break;
        } else { /* No transport coding, copy data */
            bpak_printf(2, "Copying part: %x\n", ph->id);

            rc = transport_copy(input_header,
                                output_header,
                                ph->id,
                                input_fp,
                                output_fp);

            if (rc != BPAK_OK)
                break;
        }
    }

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Failed\n", __func__);
        goto err_out;
    }

    rc = fseek(output_fp, 0, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "Error: Could not seek\n");
        rc = -BPAK_SEEK_ERROR;
        goto err_out;
    }

    written = fwrite(output_header, 1, sizeof(*output_header), output_fp);

    if (written != sizeof(*output_header)) {
        bpak_printf(0, "Error: could not write header");
        rc = -1;
    }

err_out:
    return rc;
}
