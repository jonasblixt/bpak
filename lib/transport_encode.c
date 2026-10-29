/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <bpak/bpak.h>
#include <bpak/id.h>
#include <bpak/bsdiff.h>
#include <bpak/transport.h>

#include "internal.h"

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

    rc = fseeko(input_fp, part_offset, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Could not seek input stream\n", __func__);
        return -BPAK_SEEK_ERROR;
    }

    rc = fseeko(output_fp, bpak_part_offset(output_hdr, p), SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return -BPAK_SEEK_ERROR;
    }

    rc = bpak_file_copy(input_fp, output_fp, bpak_part_size(p));

    if (rc != BPAK_OK)
        bpak_printf(0, "Error: Could not copy part %x (%i)\n", id, rc);

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

    if (bytes_written != (ssize_t)length) {
        bpak_printf(0, "Error: bsdiff_write_output write\n");
        return -BPAK_WRITE_ERROR;
    }

    return bytes_written;
}

/* Map all of 'fp', the offset of mmap must be page aligned and the offsets
 * of the parts are not */
static int map_file(FILE *fp, const char *name, uint8_t **data, size_t *size)
{
    if (fseeko(fp, 0, SEEK_END) != 0)
        return -BPAK_SEEK_ERROR;

    off_t file_size = ftello(fp);

    if (file_size == -1)
        return -BPAK_SEEK_ERROR;

    /* mmap takes a size_t */
    if ((uint64_t)file_size > SIZE_MAX)
        return -BPAK_SIZE_ERROR;

    void *map = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fileno(fp), 0);

    if (map == MAP_FAILED) {
        bpak_printf(0,
                    "Error: Could not mmap %s data (%s)\n",
                    name,
                    strerror(errno));
        return -BPAK_FAILED;
    }

    *data = map;
    *size = file_size;
    return BPAK_OK;
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
    uint8_t *origin_map = NULL;
    uint8_t *target_map = NULL;
    size_t origin_map_size = 0;
    size_t target_map_size = 0;

    memset(&priv, 0, sizeof(priv));
    priv.fd = fileno(output);

    rc = map_file(target, "target", &target_map, &target_map_size);

    if (rc != BPAK_OK)
        return rc;

    rc = map_file(origin, "origin", &origin_map, &origin_map_size);

    if (rc != BPAK_OK)
        goto err_munmap_target;

    rc = bpak_bsdiff_init(&bsdiff,
                          origin_map + origin_offset,
                          origin_length,
                          target_map + target_offset,
                          target_length,
                          bsdiff_write_output,
                          output_offset,
                          compression,
                          &priv);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: bpak_bsdiff_init failed (%zd)\n", rc);
        goto err_munmap_origin;
    }

    rc = bpak_bsdiff(&bsdiff);

    if (rc < 0) {
        bpak_printf(0, "Error: bpak_bsdiff failed (%zd)\n", rc);
        goto err_bsdiff_free;
    }

    bpak_printf(1, "bsdiff completed, output size = %zd\n", rc);

err_bsdiff_free:
    bpak_bsdiff_free(&bsdiff);
err_munmap_origin:
    munmap(origin_map, origin_map_size);
err_munmap_target:
    munmap(target_map, target_map_size);
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

    /* The output header is a copy of the input header */
    output_part = &output_header->parts[input_part - input_header->parts];

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
                "Initializing alg, input size %zu bytes\n",
                bpak_part_size(input_part));

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
        else if (alg_id == BPAK_ID_BSDIFF_LZMA)
            compression = BPAK_COMPRESSION_LZMA;

        /* bsdiff writes the output with the file descriptor, write the
         * buffered data of the stream first */
        if (fflush(output_fp) != 0) {
            rc = -BPAK_WRITE_ERROR;
            goto err_out;
        }

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
        rc = -BPAK_NOT_SUPPORTED;
        goto err_out;
    }

    if (output_size < 0) {
        bpak_printf(0, "Error: processing of part failed (%zd)\n", output_size);
        rc = output_size;
        goto err_out;
    }

    bpak_printf(1, "Done processing, output size %zd bytes\n", output_size);

    /* Update part header to indicate that the part has been coded */
    output_part->transport_size = output_size;
    output_part->flags |= BPAK_FLAG_TRANSPORT;

err_out:
    return rc;
}

BPAK_EXPORT int
bpak_transport_encode(FILE *input_fp, struct bpak_header *input_header,
                      FILE *output_fp, struct bpak_header *output_header,
                      FILE *origin_fp, struct bpak_header *origin_header)
{
    int rc = BPAK_OK;
    struct bpak_meta_header *meta = NULL;
    struct bpak_transport_meta *tm = NULL;
    ssize_t written;

    /* Origin and input package should have the same package-uuid */
    if ((origin_fp != NULL) && (origin_header != NULL)) {
        rc = bpak_same_package_uuid(origin_header, input_header);

        if (rc != BPAK_OK)
            return rc;
    }

    /* Initialize output header by copying the input header */
    memcpy(output_header, input_header, sizeof(*input_header));

    bpak_foreach_used_part (input_header, ph) {
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

    rc = fseeko(output_fp, 0, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "Error: Could not seek\n");
        rc = -BPAK_SEEK_ERROR;
        goto err_out;
    }

    written = fwrite(output_header, 1, sizeof(*output_header), output_fp);

    if (written != sizeof(*output_header)) {
        bpak_printf(0, "Error: could not write header");
        rc = -BPAK_WRITE_ERROR;
    }

err_out:
    return rc;
}
