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
#include <bpak/bsdiff_hs.h>
#include <bpak/transport.h>

static int transport_copy(struct bpak_header *hdr, uint32_t id,
                          FILE *input_fp,
                          FILE *output_fp)
{
    int rc;
    struct bpak_part_header *p = NULL;
    uint64_t part_offset = 0;

    rc = bpak_get_part(hdr, id, &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error could not get part with ref %x\n", id);
        return rc;
    }

    part_offset = bpak_part_offset(hdr, p);

    rc = fseek(input_fp, part_offset, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Could not seek input stream\n", __func__);
        return -BPAK_SEEK_ERROR;
    }

    rc = fseek(output_fp,
                 bpak_part_offset(hdr, p),
                 SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return -BPAK_SEEK_ERROR;
    }

    uint8_t buf[1024];
    uint64_t bytes_to_copy = bpak_part_size(p);
    uint64_t chunk = 0;

    while (bytes_to_copy) {
        chunk = (bytes_to_copy > sizeof(buf))?sizeof(buf):bytes_to_copy;
        uint64_t read_bytes = fread(buf, 1, chunk, input_fp);

        if (read_bytes != chunk) {
            bpak_printf(0, "Error: Could not read chunk");
            rc = -BPAK_FAILED;
            goto err_out;
        }

        uint64_t written_bytes = fwrite(buf, 1, chunk, output_fp);

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

struct bsdiff_private
{
    int fd;
    off_t offset;
    ssize_t length;
    size_t position;
};

/* Write's the compressed output of bsdiff */
static ssize_t bsdiff_write_output(off_t offset,
                                   uint8_t *buffer,
                                   size_t length,
                                   void *user_priv)
{
    struct bsdiff_private *priv = (struct bsdiff_private *) user_priv;

    if (lseek(priv->fd, priv->offset + priv->position, SEEK_SET) == -1) {
        bpak_printf(0, "Error: bsdiff_write_output seek\n");
        return -BPAK_SEEK_ERROR;
    }

    ssize_t bytes_written = write(priv->fd, buffer, length);

    if (bytes_written != length) {
        bpak_printf(0, "Error: bsdiff_write_output write\n");
        return -BPAK_WRITE_ERROR;
    }

    priv->position += bytes_written;
    priv->length += bytes_written;

    return bytes_written;
}


static ssize_t transport_bsdiff_hs(FILE *target,
                                   off_t target_offset,
                                   size_t target_length,
                                   FILE *origin,
                                   off_t origin_offset,
                                   size_t origin_length,
                                   FILE *output,
                                   off_t output_offset)
{
    ssize_t rc;
    struct bsdiff_private priv;
    struct bpak_bsdiff_hs_context bsdiff;
    uint8_t *origin_data = NULL;
    uint8_t *origin_data_mmap = NULL;
    uint8_t *target_data = NULL;
    uint8_t *target_data_mmap = NULL;
    int target_fd = fileno(target);
    int origin_fd = fileno(origin);

    memset(&priv, 0, sizeof(priv));
    priv.fd = fileno(output);
    priv.offset = output_offset;

    /* Map the entrire file because mmap's offset must be page aligned and
     * we need to handle non page aligned offsets */
    if (fseek(target, 0, SEEK_END) != 0)
        return -BPAK_SEEK_ERROR;

    size_t target_file_sz = ftell(target);
    target_data_mmap = mmap(NULL, target_file_sz, PROT_READ, MAP_SHARED,
                            target_fd, 0);

    if (((intptr_t) target_data_mmap) == -1) {
        bpak_printf(0, "Error: Could not mmap target data (%s)\n",
                        strerror(errno));
        return -BPAK_FAILED;
    }

    /* Calculate pointer to where the needed data starts */
    target_data = target_data_mmap + target_offset;

    if (fseek(origin, 0, SEEK_END) != 0)
        return -BPAK_SEEK_ERROR;

    size_t origin_file_sz = ftell(origin);
    origin_data_mmap = mmap(NULL, origin_file_sz, PROT_READ, MAP_SHARED,
                            origin_fd, 0);

    if (((intptr_t) origin_data_mmap) == -1) {
        bpak_printf(0, "Error: Could not mmap origin data (%s)\n",
                        strerror(errno));
        rc = -BPAK_FAILED;
        goto err_munmap_target;
    }

    /* Calculate pointer to where the needed data starts */
    origin_data = origin_data_mmap + origin_offset;

    rc = bpak_bsdiff_hs_init(&bsdiff, origin_data, origin_length,
                                target_data, target_length,
                                bsdiff_write_output,
                                &priv);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: bpak_bsdiff_hs_init failed (%i)\n", rc);
        goto err_munmap_origin;
    }

    rc = bpak_bsdiff_hs(&bsdiff);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: bpak_bsdiff_hs failed (%i)\n", rc);
        goto err_bsdiff_free;
    }

    bpak_printf(1, "bsdiff_hs completed, output size = %zu\n",
                    priv.length);

    rc = priv.length;
err_bsdiff_free:
    bpak_bsdiff_hs_free(&bsdiff);
err_munmap_origin:
    munmap(origin_data_mmap, origin_file_sz);
err_munmap_target:
    munmap(target_data_mmap, target_file_sz);
    return rc;
}

struct merkle_priv_ctx {
    FILE *out;
    off_t tree_offset;
};

static ssize_t merkle_tree_rd(off_t offset,
                              uint8_t *buf,
                              size_t size,
                              void *user_priv)
{
    struct merkle_priv_ctx *priv = (struct merkle_priv_ctx *) user_priv;

    int64_t pos = ftell(priv->out);

    if (fseek(priv->out, priv->tree_offset + offset,
                        SEEK_SET) != 0) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_SEEK_ERROR;
    }

    ssize_t bytes_read = fwrite(buf, 1, size, priv->out);

    if (fseek(priv->out, pos, SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle read seek error\n");
        return -BPAK_SEEK_ERROR;
    }

    return bytes_read;
}

static ssize_t merkle_tree_wr(off_t offset,
                              uint8_t *buf,
                              size_t size,
                              void *user_priv)
{
    struct merkle_priv_ctx *priv = (struct merkle_priv_ctx *) user_priv;

    int64_t pos = ftell(priv->out);

    if (fseek(priv->out, priv->tree_offset + offset,
                        SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_SEEK_ERROR;
    }

    ssize_t bytes_written = fwrite(buf, 1, size, priv->out);

    if (fseek(priv->out, pos, SEEK_SET) != 0) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_SEEK_ERROR;
    }

    return bytes_written;
}

static ssize_t transport_merkle_generate(FILE *fp,
                                         struct bpak_header *header,
                                         uint32_t merkle_tree_id,
                                         off_t offset)
{
    int rc;
    struct bpak_merkle_context merkle;
    struct merkle_priv_ctx merkle_priv;
    struct bpak_part_header *part;
    struct bpak_part_header *fs_part;
    uint8_t chunk_buffer[4096];
    uint8_t buffer2[4096];
    uint32_t fs_id = 0;
    uint8_t *salt = NULL;
    size_t bytes_to_process;
    size_t chunk_length;

    /* The part id currently begin processed is for the hash tree,
     *  Locate the filesystem that should be used */
    bpak_foreach_part(header, part) {
        if (bpak_crc32(part->id, "-hash-tree", 10) == merkle_tree_id) {
            fs_id = part->id;
            break;
        }
    }

    if (!fs_id) {
        bpak_printf(0, "Error: could not find hash tree\n");
        return -BPAK_FAILED;
    }

    /* Load the salt that should be used */
    rc = bpak_get_meta_with_ref(header, BPAK_ID_MERKLE_SALT, fs_id,
                                (void **) &salt, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not load merkle salt for part 0x%x\n",
                            fs_id);
        return rc;
    }

    /* Get filesystem header */
    fs_part = NULL;
    rc = bpak_get_part(header, fs_id, &fs_part);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not read filesystem header\n");
        return rc;
    }

    /* Init merkle private context for wr/rd callbacks */
    memset(&merkle_priv, 0, sizeof(merkle_priv));
    merkle_priv.out = fp;
    merkle_priv.tree_offset = offset + bpak_part_offset(header, fs_part) +
                                  bpak_part_size(fs_part);

    bpak_printf(2, "Tree offset: %i\n", merkle_priv.tree_offset);

    rc = bpak_merkle_init(&merkle,
                          buffer2, 4096,
                          bpak_part_size(fs_part),
                          salt,
                          merkle_tree_wr,
                          merkle_tree_rd,
                          &merkle_priv);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not init bpak merkle\n");
        return rc;
    }

    /* Position input stream to where the data starts */
    if (fseek(fp, offset + bpak_part_offset(header, fs_part),
                        SEEK_SET) != 0) {
        bpak_printf(0, "Error: seek\n");
        return -BPAK_SEEK_ERROR;
    }

    bytes_to_process = fs_part->size;
    while (bytes_to_process) {
        chunk_length = fread(chunk_buffer, 1,
                            BPAK_MIN(sizeof(chunk_buffer), bytes_to_process), fp);

        rc = bpak_merkle_process(&merkle, chunk_buffer, chunk_length);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
            return rc;
        }

        bytes_to_process -= chunk_length;
    }

    do {
        rc = bpak_merkle_process(&merkle, NULL, 0);

        if (rc != BPAK_OK) {
            bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
            return rc;
        }
    } while (bpak_merkle_done(&merkle) != true);

    bpak_merkle_hash_t roothash;
    rc = bpak_merkle_out(&merkle, roothash);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: merkle processing failed (%i)\n", rc);
        return rc;
    }

    bpak_printf(2, "merkle done (%i)\n", rc);

    if (rc == 0)
        return bpak_merkle_get_size(&merkle);
    else
        return rc;
}

static int transport_encode_part(struct bpak_transport_meta *tm,
                                 uint32_t part_ref_id,
                                 FILE *input_fp, struct bpak_header *input_header,
                                 FILE *output_fp, struct bpak_header *output_header,
                                 FILE *origin_fp, struct bpak_header *origin_header)
{
    int rc = 0;
    struct bpak_part_header *input_part = NULL;
    struct bpak_part_header *output_part = NULL;
    struct bpak_part_header *origin_part = NULL;
    uint64_t bytes_to_copy = 0;
    size_t chunk_sz = 0;
    size_t read_bytes = 0;
    size_t written_bytes = 0;
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
            bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
            return rc;
        }
    }

    alg_id = tm->alg_id_encode;
    bpak_printf(2, "Encoding part 0x%x using encoder 0x%x\n", part_ref_id,
                    alg_id);

    /* Already processed for transport ?*/
    if ((output_part->flags & BPAK_FLAG_TRANSPORT))
        return BPAK_OK;

    bpak_printf(1, "Initializing alg, input size %li bytes\n",
                bpak_part_size(input_part));

    if (origin_header != NULL) {
        rc = fseek(origin_fp,
                     bpak_part_offset(origin_header, origin_part),
                     SEEK_SET);

        if (rc != 0) {
            bpak_printf(0, "%s: Error, could not seek origin stream", __func__);
            return rc;
        }
    }

    rc = fseek(input_fp,
                 bpak_part_offset(input_header, input_part),
                 SEEK_SET);

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

    off_t output_offset = 0;
    off_t origin_offset = 0;

    switch (alg_id) {
        case BPAK_ID_BSDIFF: /* heatshrink compressor */
            if (origin_header == NULL) {
                bpak_printf(0, "Error: Need an origin stream for diff operation\n");
                rc = -BPAK_FAILED;
                goto err_out;
            }
            output_size = transport_bsdiff_hs(input_fp,
                                bpak_part_offset(input_header, input_part),
                                bpak_part_size(input_part),
                                origin_fp,
                                bpak_part_offset(origin_header, origin_part) +
                                  origin_offset,
                                bpak_part_size(origin_part),
                                output_fp,
                                bpak_part_offset(output_header, output_part) +
                                  output_offset);
        break;
        case BPAK_ID_MERKLE_GENERATE:
            output_size = transport_merkle_generate(output_fp,
                                                    output_header,
                                                    part_ref_id,
                                                    output_offset);
        break;
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
    struct bpak_transport_meta *tm = NULL;
    struct bpak_part_header *ph = NULL;
    ssize_t written;


    if ((origin_fp != NULL) && (origin_header != NULL)) {
        uint8_t *origin_package_uuid;
        uint8_t *patch_package_uuid;

        /* Origin and input package should have the same package-uuid */
        rc = bpak_get_meta(origin_header, BPAK_ID_BPAK_PACKAGE,
                                    (void **) &origin_package_uuid, NULL);

        if (rc != BPAK_OK)
            return rc;

        rc = bpak_get_meta(input_header, BPAK_ID_BPAK_PACKAGE,
                                    (void **) &patch_package_uuid, NULL);

        if (rc != BPAK_OK)
            return rc;

        if (memcmp(origin_package_uuid, patch_package_uuid, 16) != 0)
            return -BPAK_PACKAGE_UUID_MISMATCH;
    }

    /* Initialize output header by copying the input header */
    memcpy(output_header, input_header, sizeof(*input_header));

    bpak_foreach_part(input_header, ph) {
        if (ph->id == 0)
            break;

        if (bpak_get_meta_with_ref(input_header,
                                   BPAK_ID_BPAK_TRANSPORT,
                                   ph->id,
                                   (void **) &tm, NULL) == BPAK_OK) {
            bpak_printf(2, "Transport encoding part: %x\n", ph->id);

            rc = transport_encode_part(tm, ph->id,
                                   input_fp, input_header,
                                   output_fp, output_header,
                                   origin_fp, origin_header);

            if (rc != BPAK_OK)
                break;
        } else { /* No transport coding, copy data */
            bpak_printf(2, "Copying part: %x\n", ph->id);

            rc = transport_copy(input_header, ph->id, input_fp, output_fp);

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
