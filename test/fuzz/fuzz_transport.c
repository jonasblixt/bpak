/*
 * Transport decoding of untrusted patch packages, as
 * bpak_pkg_transport_decode does it, with the streams in memory.
 *
 * Input: a transport encoded package, the header followed by the encoded
 * parts. The origin is BPAK_FUZZ_ORIGIN.
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/transport.h>
#include "fuzz.h"

#define WORK_LENGTH   BPAK_CHUNK_BUFFER_LENGTH
#define OUTPUT_LENGTH (256 * 1024)

struct fuzz_transport {
    uint8_t *origin;
    size_t origin_size;
    uint8_t *output;
    size_t output_size;
    struct bpak_header output_header;
};

static int bounded(off_t offset, size_t length, size_t size)
{
    return offset >= 0 && (size_t)offset <= size &&
           length <= size - (size_t)offset;
}

static ssize_t write_output(off_t offset, uint8_t *buffer, size_t length,
                            void *user)
{
    struct fuzz_transport *f = user;

    if (!bounded(offset, length, f->output_size))
        return -BPAK_WRITE_ERROR;

    memcpy(&f->output[offset], buffer, length);
    return length;
}

static ssize_t read_output(off_t offset, uint8_t *buffer, size_t length,
                           void *user)
{
    struct fuzz_transport *f = user;

    if (!bounded(offset, length, f->output_size))
        return -BPAK_READ_ERROR;

    memcpy(buffer, &f->output[offset], length);
    return length;
}

static ssize_t write_output_header(off_t offset, uint8_t *buffer, size_t length,
                                   void *user)
{
    struct fuzz_transport *f = user;
    (void)offset;

    FUZZ_ASSERT(length == sizeof(f->output_header));
    memcpy(&f->output_header, buffer, length);
    return length;
}

static ssize_t read_origin(off_t offset, uint8_t *buffer, size_t length,
                           void *user)
{
    struct fuzz_transport *f = user;

    /* bspatch reads into the first half of the work buffer */
    FUZZ_ASSERT(length <= WORK_LENGTH / 2);

    if (!bounded(offset, length, f->origin_size))
        return -BPAK_READ_ERROR;

    memcpy(buffer, &f->origin[offset], length);
    return length;
}

static void load_origin(struct fuzz_transport *f)
{
    FILE *fp = fopen(BPAK_FUZZ_ORIGIN, "rb");
    long size;

    FUZZ_ASSERT(fp != NULL);
    FUZZ_ASSERT(fseek(fp, 0, SEEK_END) == 0);
    size = ftell(fp);
    FUZZ_ASSERT(size >= (long)sizeof(struct bpak_header));
    FUZZ_ASSERT(fseek(fp, 0, SEEK_SET) == 0);

    f->origin = malloc(size);
    FUZZ_ASSERT(f->origin != NULL);
    FUZZ_ASSERT(fread(f->origin, 1, size, fp) == (size_t)size);
    f->origin_size = size;
    fclose(fp);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static struct fuzz_transport f;
    struct bpak_header *patch_header = malloc(sizeof(*patch_header));
    struct bpak_header *origin_header = malloc(sizeof(*origin_header));
    uint8_t *work = malloc(WORK_LENGTH);
    struct bpak_transport_decode ctx;
    size_t input_offset = sizeof(*patch_header);
    int rc;

    FUZZ_ASSERT(patch_header != NULL && origin_header != NULL);
    FUZZ_ASSERT(work != NULL);

    if (f.origin == NULL) {
        load_origin(&f);
        f.output_size = OUTPUT_LENGTH;
        f.output = malloc(f.output_size);
        FUZZ_ASSERT(f.output != NULL);
    }

    memset(f.output, 0, f.output_size);
    memcpy(origin_header, f.origin, sizeof(*origin_header));

    if (size < sizeof(*patch_header))
        goto out;

    /* As bpak_pkg_open */
    memcpy(patch_header, data, sizeof(*patch_header));

    if (bpak_valid_header(patch_header) != BPAK_OK)
        goto out;

    rc = bpak_transport_decode_init(&ctx,
                                    work,
                                    WORK_LENGTH,
                                    patch_header,
                                    write_output,
                                    read_output,
                                    sizeof(struct bpak_header),
                                    write_output_header,
                                    &f);

    if (rc != BPAK_OK)
        goto out;

    rc = bpak_transport_decode_set_origin(&ctx,
                                          origin_header,
                                          read_origin,
                                          sizeof(struct bpak_header));

    if (rc != BPAK_OK)
        goto out_free;

    bpak_foreach_part (patch_header, part) {
        struct bpak_part_header *origin_part = NULL;

        if (part->id == 0)
            break;

        if (bpak_get_part(origin_header, part->id, &origin_part) != BPAK_OK)
            break;

        if (bpak_transport_decode_start(&ctx, part) != BPAK_OK)
            break;

        size_t bytes_to_process = bpak_part_size(part);

        rc = BPAK_OK;

        while (bytes_to_process && rc == BPAK_OK) {
            size_t chunk_length = BPAK_MIN(bytes_to_process, WORK_LENGTH);
            /* Exactly sized, a copy of the chunk */
            uint8_t *chunk;

            if (input_offset > size || chunk_length > size - input_offset) {
                rc = -BPAK_READ_ERROR;
                break;
            }

            chunk = malloc(chunk_length);
            FUZZ_ASSERT(chunk != NULL);
            memcpy(chunk, &data[input_offset], chunk_length);
            rc = bpak_transport_decode_write_chunk(&ctx, chunk, chunk_length);
            free(chunk);

            input_offset += chunk_length;
            bytes_to_process -= chunk_length;
        }

        if (rc != BPAK_OK)
            break;

        if (bpak_transport_decode_finish(&ctx) != BPAK_OK)
            break;
    }

out_free:
    bpak_transport_decode_free(&ctx);
out:
    free(work);
    free(origin_header);
    free(patch_header);
    return 0;
}
