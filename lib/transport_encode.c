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
#include <bpak/pkg.h>
#include <bpak/file.h>
#include <bpak/utils.h>
#include <bpak/merkle.h>
#include <bpak/bsdiff.h>
#include <bpak/bsdiff_hs.h>
#include <bpak/transport.h>
#include "sha256.h"
#include "sha512.h"

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

    rc = bpak_io_seek(output_io,
                 bpak_part_offset(hdr, p),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return rc;
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


static ssize_t transport_bsdiff_hs(struct bpak_io *target,
                                   off_t target_offset,
                                   size_t target_length,
                                   struct bpak_io *origin,
                                   off_t origin_offset,
                                   size_t origin_length,
                                   struct bpak_io *output,
                                   off_t output_offset)
{
    ssize_t rc;
    struct bsdiff_private priv;
    struct bpak_bsdiff_hs_context bsdiff;
    uint8_t *origin_data = NULL;
    uint8_t *origin_data_mmap = NULL;
    uint8_t *target_data = NULL;
    uint8_t *target_data_mmap = NULL;
    int target_fd = bpak_io_file_to_fd(target);
    int origin_fd = bpak_io_file_to_fd(origin);

    memset(&priv, 0, sizeof(priv));
    priv.fd = bpak_io_file_to_fd(output);
    priv.offset = output_offset;

    /* Map the entrire file because mmap's offset must be page aligned and
     * we need to handle non page aligned offsets */
    target_data_mmap = mmap(NULL, target->end_position, PROT_READ, MAP_SHARED,
                            target_fd, 0);

    if (((intptr_t) target_data_mmap) == -1) {
        bpak_printf(0, "Error: Could not mmap target data (%s)\n",
                        strerror(errno));
        return -BPAK_FAILED;
    }

    /* Calculate pointer to where the needed data starts */
    target_data = target_data_mmap + target_offset;

    origin_data_mmap = mmap(NULL, origin->end_position, PROT_READ, MAP_SHARED,
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
    munmap(origin_data_mmap, origin->end_position);
err_munmap_target:
    munmap(target_data_mmap, target->end_position);
    return rc;
}

struct merkle_priv_ctx {
    struct bpak_io *out;
    off_t tree_offset;
};

static ssize_t merkle_tree_rd(off_t offset,
                              uint8_t *buf,
                              size_t size,
                              void *user_priv)
{
    struct merkle_priv_ctx *priv = (struct merkle_priv_ctx *) user_priv;

    int64_t pos = bpak_io_tell(priv->out);

    if (bpak_io_seek(priv->out, priv->tree_offset + offset,
                        BPAK_IO_SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_FAILED;
    }

    ssize_t bytes_read = bpak_io_read(priv->out, buf, size);

    if (bpak_io_seek(priv->out, pos, BPAK_IO_SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle read seek error\n");
        return -BPAK_FAILED;
    }

    return bytes_read;
}

static ssize_t merkle_tree_wr(off_t offset,
                              uint8_t *buf,
                              size_t size,
                              void *user_priv)
{
    struct merkle_priv_ctx *priv = (struct merkle_priv_ctx *) user_priv;

    int64_t pos = bpak_io_tell(priv->out);

    if (bpak_io_seek(priv->out, priv->tree_offset + offset,
                        BPAK_IO_SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_FAILED;
    }

    ssize_t bytes_written = bpak_io_write(priv->out, buf, size);

    if (bpak_io_seek(priv->out, pos, BPAK_IO_SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: merkle write seek error\n");
        return -BPAK_FAILED;
    }

    return bytes_written;
}

static ssize_t transport_merkle_generate(struct bpak_io *io,
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
                                   /*  id("merkle-salt") */
    rc = bpak_get_meta_with_ref(header,  0x7c9b2f93, fs_id, (void **) &salt,
                                NULL);

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
    merkle_priv.out = io;
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
    if (bpak_io_seek(io, offset + bpak_part_offset(header, fs_part),
                        BPAK_IO_SEEK_SET) != BPAK_OK) {
        bpak_printf(0, "Error: seek\n");
        return -BPAK_FAILED;
    }

    bytes_to_process = fs_part->size;
    while (bytes_to_process) {
        chunk_length = bpak_io_read(io, chunk_buffer,
                            BPAK_MIN(sizeof(chunk_buffer), bytes_to_process));

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

static int transport_process(struct bpak_transport_meta *tm,
                                 uint32_t part_ref_id,
                                 struct bpak_package *input,
                                 struct bpak_package *output,
                                 struct bpak_package *origin)
{
    int rc = 0;
    struct bpak_part_header *input_part = NULL;
    struct bpak_part_header *output_part = NULL;
    struct bpak_part_header *origin_part = NULL;
    struct bpak_io *input_io = input->io;
    struct bpak_io *output_io = output->io;
    struct bpak_io *origin_io = NULL;
    uint64_t bytes_to_copy = 0;
    size_t chunk_sz = 0;
    size_t read_bytes = 0;
    size_t written_bytes = 0;
    uint32_t alg_id = 0;
    ssize_t output_size = -1;
    struct bpak_header *input_header = bpak_pkg_header(input);
    struct bpak_header *output_header = bpak_pkg_header(output);
    struct bpak_header *origin_header = bpak_pkg_header(origin);

    if (origin) {
        origin_io = origin->io;
    }

    rc = bpak_get_part(input_header, part_ref_id, &input_part);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    rc = bpak_get_part(output_header, part_ref_id, &output_part);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    rc = bpak_get_part(origin_header, part_ref_id, &origin_part);

    if (rc != BPAK_OK)
    {
        bpak_printf(0, "Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    bpak_printf(2, "Encoding part %x (%p)\n", part_ref_id, input_part);

    alg_id = tm->alg_id_encode;

    bpak_printf(2, "Using alg: %x\n", alg_id);

    /* Already processed for transport ?*/
    if ((output_part->flags & BPAK_FLAG_TRANSPORT))
        return BPAK_OK;

    /* Populate the header in the output stream */
    bpak_io_seek(output_io, 0, BPAK_IO_SEEK_SET);
    bpak_io_write(output_io, output_header, sizeof(*output_header));

    bpak_printf(1, "Initializing alg, input size %li bytes\n",
                bpak_part_size(input_part));

    rc = bpak_io_seek(origin_io,
                 bpak_part_offset(origin_header, origin_part),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek origin stream", __func__);
        return rc;
    }

    rc = bpak_io_seek(input_io,
                 bpak_part_offset(input_header, input_part),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek input stream", __func__);
        return rc;
    }

    rc = bpak_io_seek(output_io,
                 bpak_part_offset(output_header, output_part),
                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error, could not seek output stream", __func__);
        return rc;
    }

    off_t output_offset = 0;
    off_t origin_offset = 0;

    if (origin->header_location == BPAK_HEADER_POS_LAST) {
        origin_offset = -sizeof(struct bpak_header);
    }

    switch (alg_id) {
        case 0x9f7aacf9: /* id("bsdiff") heatshrink compressor */
            output_size = transport_bsdiff_hs(input_io,
                                bpak_part_offset(input_header, input_part),
                                bpak_part_size(input_part),
                                origin_io,
                                bpak_part_offset(origin_header, origin_part) +
                                  origin_offset,
                                bpak_part_size(origin_part),
                                output_io,
                                bpak_part_offset(output_header, output_part) +
                                  output_offset);
        break;
        case 0xb5bcc58f: /* id("merkle-generate") */
            output_size = transport_merkle_generate(output_io,
                                                    &output->header,
                                                    part_ref_id,
                                                    output_offset);
        break;
        case 0x57004cd0: /* id("remove-data") */
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

    /* Position output stream at the end of the processed part*/
    rc = bpak_io_seek(output_io, bpak_part_offset(output_header, output_part) +
                                 bpak_part_size(output_part),
                                 BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "%s: Error: Could not seek\n", __func__);
        bpak_printf(0, "    offset: %li\n", bpak_part_offset(output_header, output_part));
        bpak_printf(0, "    size:   %li\n", bpak_part_size(output_part));
        goto err_out;
    }

err_out:
    return rc;
}

int bpak_transport_encode(struct bpak_package *input,
                          struct bpak_package *output,
                          struct bpak_package *origin)
{
    int rc = BPAK_OK;
    struct bpak_header *h = bpak_pkg_header(input);
    struct bpak_header *oh = bpak_pkg_header(output);
    struct bpak_transport_meta *tm = NULL;
    struct bpak_part_header *ph = NULL;
    ssize_t written;
    memcpy(oh, h, sizeof(*h));

    bpak_foreach_part(&input->header, ph) {
        if (ph->id == 0)
            break;

        if (bpak_get_meta_with_ref(&input->header,
                                   bpak_id("bpak-transport"),
                                   ph->id,
                                   (void **) &tm, NULL) == BPAK_OK) {
            bpak_printf(2, "Transport encoding part: %x\n", ph->id);

            rc = transport_process(tm, ph->id,
                                   input, output, origin);

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

    // TODO: Header at the end?
    rc = bpak_io_seek(output->io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not seek\n");
        goto err_out;
    }

    written = bpak_io_write(output->io, oh, sizeof(*oh));

    if (written != sizeof(*oh)) {
        bpak_printf(0, "Error: could not write header");
        rc = -1;
    }

err_out:
    return rc;
}
