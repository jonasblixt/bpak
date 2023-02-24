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
#include <bpak/verify.h>
#include <bpak/crc.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>
#include <bpak/transport.h>

BPAK_EXPORT int bpak_pkg_open(struct bpak_package *pkg, const char *filename,
                              const char *mode)
{
    int rc;

    if (!mode)
        return -BPAK_FAILED;

    bpak_printf(1, "Opening BPAK file %s\n", filename);

    memset(pkg, 0, sizeof(*pkg));

    pkg->fp = fopen(filename, mode);

    if (pkg->fp == NULL)
        return -BPAK_NOT_FOUND;

    if (fseek(pkg->fp, 0, SEEK_SET) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_close_io;
    }

    size_t read_bytes = fread(&pkg->header, 1, sizeof(pkg->header), pkg->fp);

    if (read_bytes != sizeof(pkg->header)) {
        goto skip_header;
    }

    rc = bpak_valid_header(&pkg->header);

    if (rc != BPAK_OK) {
        goto err_close_io;
    }

skip_header:
    if (fseek(pkg->fp, 0, SEEK_SET) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_close_io;
    }

    return BPAK_OK;

err_close_io:
    fclose(pkg->fp);
    return rc;
}

BPAK_EXPORT int bpak_pkg_close(struct bpak_package *pkg)
{
    if (pkg->fp != NULL) {
        fclose(pkg->fp);
        pkg->fp = NULL;
    }
    return BPAK_OK;
}

static ssize_t pkg_read_payload(off_t offset, uint8_t *buf, size_t length,
                                void *user)
{
    FILE *fp = (FILE *)user;
    if (fseek(fp, offset, SEEK_SET) != 0)
        return -BPAK_SEEK_ERROR;
    size_t read_bytes = fread(buf, 1, length, fp);

    if (read_bytes != length)
        return -BPAK_READ_ERROR;

    return read_bytes;
}

BPAK_EXPORT int bpak_pkg_update_hash(struct bpak_package *pkg, char *output,
                                     size_t *size)
{
    int rc;

    size_t hash_size = sizeof(pkg->header.payload_hash);

    rc = bpak_verify_compute_payload_hash(&pkg->header,
                                          pkg_read_payload,
                                          sizeof(struct bpak_header),
                                          (void *)pkg->fp,
                                          pkg->header.payload_hash,
                                          &hash_size);

    if (rc != BPAK_OK)
        return rc;

    if ((output != NULL) && (size != NULL)) {
        rc = bpak_verify_compute_header_hash(&pkg->header,
                                             (uint8_t *)output,
                                             size);
        if (rc != BPAK_OK)
            return rc;
    }

    return BPAK_OK;
}

BPAK_EXPORT size_t bpak_pkg_installed_size(struct bpak_package *pkg)
{
    size_t installed_size = 0;

    bpak_foreach_part (&pkg->header, p) {
        installed_size += p->size + p->pad_bytes;
    }

    return installed_size;
}

BPAK_EXPORT size_t bpak_pkg_size(struct bpak_package *pkg)
{
    size_t transport_size = 0;

    bpak_foreach_part (&pkg->header, p) {
        if (p->flags & BPAK_FLAG_TRANSPORT)
            transport_size += p->transport_size;
        else
            transport_size += p->size;
    }

    transport_size += sizeof(struct bpak_header);

    return transport_size;
}

BPAK_EXPORT struct bpak_header *bpak_pkg_header(struct bpak_package *pkg)
{
    return &pkg->header;
}

BPAK_EXPORT int bpak_pkg_write_header(struct bpak_package *pkg)
{
    if (fseek(pkg->fp, 0, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    size_t bytes_written =
        fwrite(&pkg->header, 1, sizeof(pkg->header), pkg->fp);

    if (bytes_written != sizeof(pkg->header)) {
        bpak_printf(0, "%s: Write failed\n", __func__);
        return -BPAK_WRITE_ERROR;
    }

    return BPAK_OK;
}

BPAK_EXPORT int bpak_pkg_write_raw_signature(struct bpak_package *pkg,
                                             const uint8_t *signature,
                                             size_t size)
{
    memset(pkg->header.signature, 0, sizeof(pkg->header.signature));
    memcpy(pkg->header.signature, signature, size);
    pkg->header.signature_sz = size;
    return bpak_pkg_write_header(pkg);
}

struct decode_private {
    FILE *output_fp;
    FILE *origin_fp;
};

static ssize_t decode_write_output(off_t offset, uint8_t *buffer, size_t length,
                                   void *user)
{
    struct decode_private *priv = (struct decode_private *)user;

    if (fseek(priv->output_fp, offset, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    return fwrite(buffer, 1, length, priv->output_fp);
}

static ssize_t decode_read_output(off_t offset, uint8_t *buffer, size_t length,
                                  void *user)
{
    struct decode_private *priv = (struct decode_private *)user;

    if (fseek(priv->output_fp, offset, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    return fread(buffer, 1, length, priv->output_fp);
}

static ssize_t decode_write_output_header(off_t offset, uint8_t *buffer,
                                          size_t length, void *user)
{
    struct decode_private *priv = (struct decode_private *)user;
    (void)offset;

    if (length != sizeof(struct bpak_header))
        return -BPAK_SIZE_ERROR;

    if (fseek(priv->output_fp, 0, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    return fwrite(buffer, 1, length, priv->output_fp);
}

static ssize_t decode_read_origin(off_t offset, uint8_t *buffer, size_t length,
                                  void *user)
{
    struct decode_private *priv = (struct decode_private *)user;

    if (fseek(priv->origin_fp, offset, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    return fread(buffer, 1, length, priv->origin_fp);
}

BPAK_EXPORT int bpak_pkg_transport_decode(struct bpak_package *input,
                                          struct bpak_package *output,
                                          struct bpak_package *origin)
{
    int rc;

    struct bpak_header *patch_header = bpak_pkg_header(input);
    struct bpak_part_header *origin_part = NULL;
    struct bpak_transport_decode decode_ctx;
    uint8_t chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    uint8_t decode_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    struct decode_private decode_private;

    memset(&decode_private, 0, sizeof(struct decode_private));
    decode_private.output_fp = output->fp;
    if (origin != NULL)
        decode_private.origin_fp = origin->fp;
    else
        decode_private.origin_fp = NULL;

    rc = bpak_transport_decode_init(&decode_ctx,
                                    decode_buffer,
                                    BPAK_CHUNK_BUFFER_LENGTH,
                                    patch_header,
                                    decode_write_output,
                                    decode_read_output,
                                    sizeof(struct bpak_header),
                                    decode_write_output_header,
                                    &decode_private);

    if (rc != BPAK_OK) {
        bpak_printf(0,
                    "%s: Error: Transport decode init failed (%i) %s",
                    __func__,
                    rc,
                    bpak_error_string(rc));
        goto err_out;
    }

    if (origin != NULL) {
        struct bpak_header *origin_header = bpak_pkg_header(origin);

        rc = bpak_transport_decode_set_origin(&decode_ctx,
                                              origin_header,
                                              decode_read_origin,
                                              sizeof(struct bpak_header));

        if (rc != BPAK_OK) {
            bpak_printf(0,
                        "Error: Origin stream init failed (%i) %s\n",
                        rc,
                        bpak_error_string(rc));
            goto err_out;
        }
    }

    if (fseek(input->fp, sizeof(struct bpak_header), SEEK_SET) != 0) {
        bpak_printf(0, "%s: Error, could not seek input stream", __func__);
        return -BPAK_SEEK_ERROR;
    }

    bpak_foreach_part (patch_header, part) {
        if (part->id == 0)
            break;

        /* Compute origin and output offsets */
        if (origin != NULL) {
            rc = bpak_get_part(&origin->header, part->id, &origin_part);

            if (rc != BPAK_OK) {
                bpak_printf(0,
                            "Error could not get part with ref %x\n",
                            part->id);
                goto err_out;
            }
        }

        rc = bpak_transport_decode_start(&decode_ctx, part);

        if (rc != BPAK_OK) {
            bpak_printf(0,
                        "Error: Decoder start failed for part 0x%x (%i)\n",
                        part->id,
                        rc);
            goto err_out;
        }

        /* If there is any input data chunk it up and feed the decoder */
        size_t bytes_to_process = bpak_part_size(part);

        while (bytes_to_process) {
            size_t chunk_length =
                BPAK_MIN(bytes_to_process, sizeof(chunk_buffer));
            size_t bytes_read = fread(chunk_buffer, 1, chunk_length, input->fp);

            if (bytes_read != chunk_length) {
                bpak_printf(0, "%s: bytes_read != chunk_length\n", __func__);
                return -BPAK_READ_ERROR;
            }

            rc = bpak_transport_decode_write_chunk(&decode_ctx,
                                                   chunk_buffer,
                                                   chunk_length);

            if (rc != BPAK_OK) {
                bpak_printf(
                    0,
                    "Error: Decoder write chunk failed for part 0x%x (%i)\n",
                    part->id,
                    rc);
                goto err_out;
            }

            bytes_to_process -= chunk_length;
        }

        rc = bpak_transport_decode_finish(&decode_ctx);

        if (rc != BPAK_OK) {
            bpak_printf(0,
                        "Error: Decoder finish failed for part 0x%x (%i)\n",
                        part->id,
                        rc);
            goto err_out;
        }
    }

err_out:
    bpak_transport_decode_free(&decode_ctx);
    return rc;
}

BPAK_EXPORT int bpak_pkg_transport_encode(struct bpak_package *input,
                                          struct bpak_package *output,
                                          struct bpak_package *origin)
{
    FILE *origin_fp = NULL;
    struct bpak_header *origin_header = NULL;

    if (origin != NULL) {
        if (origin->fp != NULL) {
            origin_fp = origin->fp;
            origin_header = &origin->header;
        }
    }

    return bpak_transport_encode(input->fp,
                                 &input->header,
                                 output->fp,
                                 &output->header,
                                 origin_fp,
                                 origin_header);
}

BPAK_EXPORT int bpak_pkg_extract_file(struct bpak_package *pkg,
                                      bpak_id_t part_id,
                                      const char *filename)
{
    int rc = BPAK_OK;
    uint64_t p_offset = 0;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *part = NULL;
    FILE* fp;

    rc = bpak_get_part(h, part_id, &part);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: No such part!\n", __func__);
        return rc;
    }

    p_offset = bpak_part_offset(h, part);

    if (fseek(pkg->fp, p_offset, SEEK_SET) != 0) {
        return -BPAK_SEEK_ERROR;
    }

    if (filename != NULL) {
        fp = fopen(filename, "w+b");

        if (fp == NULL) {
            bpak_printf(0, "%s: Error: Could not create '%s'\n",
                        __func__, filename);
            return -BPAK_WRITE_ERROR;
        }
    } else {
        fp = stdout;
    }

    char copy_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    size_t bytes_to_copy = bpak_part_size(part) - part->pad_bytes;
    size_t chunk_to_write = 0;
    size_t chunk_read = 0;

    while (bytes_to_copy) {
        if (bytes_to_copy > sizeof(copy_buffer)) {
            chunk_to_write = sizeof(copy_buffer);
        } else {
            chunk_to_write = bytes_to_copy;
        }

        chunk_read = fread(copy_buffer, 1, chunk_to_write, pkg->fp);
        if (chunk_read != chunk_to_write) {
            rc = -BPAK_READ_ERROR;
            goto err_close_fp_out;
        }


        if (fwrite(copy_buffer, 1, chunk_read, fp) != chunk_read) {
            rc = -BPAK_WRITE_ERROR;
            goto err_close_fp_out;
        }

        bytes_to_copy -= chunk_to_write;
    }

err_close_fp_out:
    if ((fp != stdout) && (fp != NULL)) {
        fclose(fp);
    }

    return rc;
}

BPAK_EXPORT int bpak_pkg_delete_part(struct bpak_package *pkg,
                                     bpak_id_t part_id, bool remove_meta)
{
    int rc = BPAK_OK;
    uint64_t p_offset;
    size_t p_size;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *part = NULL;

    bpak_printf(1, "Deleting 0x%08x\n", part_id);

    rc = bpak_get_part(h, part_id, &part);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: No such part!\n", __func__);
        return rc;
    }

    p_offset = bpak_part_offset(h, part);
    p_size = bpak_part_size(part);

    bpak_del_part(h, part);
    uint64_t bytes_to_process = 0;

    /* Part now points to what previously was the part after the one we remove */
    for (; part != &(h->parts[BPAK_MAX_PARTS]); part++) {
        if (!part->id)
            break;

        part->offset -= p_size;
        bytes_to_process += bpak_part_size(part);
    }

    /* Remove any meta-data that points to the part */
    if (remove_meta) {
        bpak_foreach_meta(h, meta) {
            if (meta->part_id_ref == part_id) {
                bpak_del_meta(h, meta);
                /* Need to step back as "meta" now points to one beyond the removed element */
                meta--;
            }
        }
    }

    /* Move the actual data, range [p_offset+p_size  end) to [p_offset  end-p_size)
     * and then truncate the file
     */
    uint64_t write_offset = p_offset;
    uint64_t read_offset = p_offset + p_size;
    char copy_buffer[BPAK_CHUNK_BUFFER_LENGTH];

    while (bytes_to_process > 0) {
        if (fseek(pkg->fp, read_offset, SEEK_SET) != 0) {
            bpak_printf(0, "%s: Error: Couldn't read file: %s\n",
                        __func__, strerror(errno));
            return -BPAK_READ_ERROR;
        }

        size_t chunk_length =
            BPAK_MIN(bytes_to_process, sizeof(copy_buffer));
        size_t chunk_read = fread(copy_buffer, 1, BPAK_CHUNK_BUFFER_LENGTH, pkg->fp);

        if (chunk_read != chunk_length) {
            rc = ferror(pkg->fp);
            if (rc != 0) {
                bpak_printf(0, "%s: Error: Couldn't read file: %d\n",
                            __func__, rc);
                return -BPAK_READ_ERROR;
            }
        }

        if (fseek(pkg->fp, write_offset, SEEK_SET) != 0 ||
            fwrite(copy_buffer, 1, chunk_read, pkg->fp) != chunk_read) {
            bpak_printf(0, "%s: Error: Couldn't write file: %s\n",
                        __func__, strerror(errno));
            return -BPAK_WRITE_ERROR;
        }

        bytes_to_process -= chunk_read;
        read_offset += chunk_read;
        write_offset += chunk_read;
    }

    p_offset = ftell(pkg->fp);

    if ((long) p_offset == -1) {
        if (rc != 0) {
            bpak_printf(0, "%s: Error: Couldn't read file: %d\n",
                        __func__, errno);
            return -BPAK_READ_ERROR;
        }
    }

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not update payload hash\n", __func__);
        return rc;
    }

    rc = bpak_pkg_write_header(pkg);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not write header\n", __func__);
        return rc;
    }

    fflush(pkg->fp);

    if (ftruncate(fileno(pkg->fp), p_offset) != 0) {
        bpak_printf(0, "%s: Error: Couldn't truncate file: %s\n",
                    __func__, strerror(errno));
        return -BPAK_WRITE_ERROR;
    }

    return BPAK_OK;
}

BPAK_EXPORT int bpak_pkg_delete_all_parts(struct bpak_package *pkg, bool remove_meta)
{
    struct bpak_header *h = bpak_pkg_header(pkg);
    int rc;

    /* Clear out all parts data */
    memset(h->parts, 0, sizeof(h->parts));

    /* Remove any meta-data that points to any part */
    if (remove_meta) {
        bpak_foreach_meta(h, meta) {
            if (meta->part_id_ref != 0) {
                bpak_del_meta(h, meta);
                /* Need to step back as "meta" now points to one beyond the removed element */
                meta--;
            }
        }
    }

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not update payload hash\n", __func__);
        return rc;
    }

    rc = bpak_pkg_write_header(pkg);
    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not write header\n", __func__);
        return rc;
    }

    fflush(pkg->fp);

    if (ftruncate(fileno(pkg->fp), sizeof(struct bpak_header)) != 0) {
        bpak_printf(0, "%s: Error: Couldn't truncate file: %s\n",
                    __func__, strerror(errno));
        return -BPAK_WRITE_ERROR;
    }

    return BPAK_OK;
}
