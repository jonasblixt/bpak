/*
 * bspatch on untrusted patches.
 *
 * Input: one byte compression (0 none, 1 heatshrink, 2 lzma), one byte
 * chunk length (the patch is fed in chunks of 1 to 256 bytes) and the patch.
 * The origin is ORIGIN_LENGTH bytes of fuzz_origin().
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/bspatch.h>
#include "fuzz.h"

#define ORIGIN_LENGTH 4096
#define OUTPUT_LENGTH (4 * ORIGIN_LENGTH)
#define WORK_LENGTH   BPAK_CHUNK_BUFFER_LENGTH

struct fuzz_bspatch {
    uint8_t origin[ORIGIN_LENGTH];
    uint8_t output[OUTPUT_LENGTH];
};

void fuzz_origin(uint8_t *origin, size_t length)
{
    /* Mostly text like repetitive data, bsdiff finds matches in it */
    for (size_t i = 0; i < length; i++)
        origin[i] = 'a' + (i * 7 + i / 64) % 26;
}

static ssize_t read_origin(off_t offset, uint8_t *buffer, size_t length,
                           void *user)
{
    struct fuzz_bspatch *f = user;

    /* bspatch reads into the first half of the work buffer */
    FUZZ_ASSERT(length <= WORK_LENGTH / 2);

    if (offset < 0 || (size_t)offset > sizeof(f->origin) ||
        length > sizeof(f->origin) - (size_t)offset)
        return -BPAK_READ_ERROR;

    memcpy(buffer, &f->origin[offset], length);
    return length;
}

static ssize_t write_output(off_t offset, uint8_t *buffer, size_t length,
                            void *user)
{
    struct fuzz_bspatch *f = user;

    if (offset < 0 || (size_t)offset > sizeof(f->output) ||
        length > sizeof(f->output) - (size_t)offset)
        return -BPAK_WRITE_ERROR;

    /* Reads 'length' bytes of 'buffer', AddressSanitizer detects reads past
     * the buffers of bspatch and of the input chunk */
    memcpy(&f->output[offset], buffer, length);
    return length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static struct fuzz_bspatch f;
    static bool initialized;
    struct bpak_bspatch_context ctx;
    uint8_t *work = malloc(WORK_LENGTH);
    enum bpak_compression compression;
    size_t chunk_length;
    int rc;

    FUZZ_ASSERT(work != NULL);

    if (!initialized) {
        fuzz_origin(f.origin, sizeof(f.origin));
        initialized = true;
    }

    if (size < 2)
        goto out;

    switch (data[0] % 3) {
    case 0:
        compression = BPAK_COMPRESSION_NONE;
        break;
    case 1:
        compression = BPAK_COMPRESSION_HS;
        break;
    default:
        compression = BPAK_COMPRESSION_LZMA;
        break;
    }

    chunk_length = (size_t)data[1] + 1;
    data += 2;
    size -= 2;

    rc = bpak_bspatch_init(&ctx,
                           work,
                           WORK_LENGTH,
                           size,
                           read_origin,
                           0,
                           write_output,
                           0,
                           compression,
                           &f);

    if (rc != BPAK_OK)
        goto out;

    for (size_t pos = 0; pos < size && rc == BPAK_OK; pos += chunk_length) {
        size_t length = BPAK_MIN(chunk_length, size - pos);
        /* Exactly sized, a copy of the chunk */
        uint8_t *chunk = malloc(length);

        FUZZ_ASSERT(chunk != NULL);
        memcpy(chunk, &data[pos], length);
        rc = bpak_bspatch_write(&ctx, chunk, length);
        free(chunk);
    }

    if (rc == BPAK_OK) {
        ssize_t output_length = bpak_bspatch_final(&ctx);

        FUZZ_ASSERT(output_length < 0 ||
                    (size_t)output_length <= sizeof(f.output));
    }

    bpak_bspatch_free(&ctx);

out:
    free(work);
    return 0;
}
