#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/bspatch.h>
#include <bpak/bsdiff.h>
#include "nala.h"

struct bspatch_priv
{
    uint8_t *origin_data;
    ssize_t origin_length;
    uint8_t *output_data;
    ssize_t output_length;
};

static ssize_t load_file(const char *dir, const char *fn, uint8_t **buffer_out)
{
    char path[256];

    sprintf(path, "%s/%s", dir, fn);

    printf("Loading: %s\n", path);
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return -1;

    off_t file_length = lseek(fd, 0, SEEK_END);

    if (file_length < 0) {
        printf("seek failed");
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    printf("Need to allocate %li bytes\n", file_length);

    (*buffer_out) = malloc(file_length);

    return read(fd, *buffer_out, file_length);
}

ssize_t read_origin(off_t offset,
                    uint8_t *buffer,
                    size_t length,
                    void *user_priv)
{
    struct bspatch_priv *priv = (struct bspatch_priv *) user_priv;

    printf("Read origin %li %zu\n", offset, length);

    ssize_t bytes_to_read = ((offset + length) > priv->origin_length)?
                            (priv->origin_length - offset):length;

    if (bytes_to_read > 0) {
        memcpy(buffer, &priv->origin_data[offset], bytes_to_read);
    }

    return bytes_to_read;
}

ssize_t write_output(off_t offset,
                    uint8_t *buffer,
                    size_t length,
                    void *user_priv)
{

    struct bspatch_priv *priv = (struct bspatch_priv *) user_priv;

    printf("Write output %li %zu\n", offset, length);
    ssize_t bytes_to_write = ((offset + length) > priv->output_length)?
                              (priv->output_length - offset): length;

    if (bytes_to_write > 0) {
        memcpy(&priv->output_data[offset], buffer, bytes_to_write);
    }

    return bytes_to_write;
}

static uint8_t *create_origin_data(size_t length)
{
    uint8_t *output = malloc(length);
    ASSERT(output != NULL);

    for (unsigned int i = 0; i < length; i++)
        output[i] = 33 + i%200;

    return output;
}

static uint8_t *create_new_data(size_t length, uint8_t *origin_data)
{
    uint8_t *output = malloc(length);
    const char *new_data = "HELLO BSPATCH";
    ASSERT(output != NULL);

    memcpy(output, origin_data, length);
    // Change some data
    memcpy(&output[500], new_data, 13);
    // Remove a block of data
    memset(&output[2048], 0, 512);

    return output;
}

static size_t patch_length;

static ssize_t write_patch_output(off_t offset,
                                  uint8_t *buffer,
                                  size_t length,
                                  void *user_priv)
{
    uint8_t *buf = (uint8_t *) user_priv;
    printf("patch write: %li, %zu\n", offset, length);
    memcpy(&buf[offset], buffer, length);
    patch_length += length;
    return length;
}
/**
 *
 * Tests both the bsdiff and bspatch algs without any compression
 *
 * 1. Generate origin test data
 * 2. Generate 'new' data based on origin data
 * 3. Create patch
 * 4. Apply patch
 * 5. Verify result
 */

#define DIFF_PATCH_NO_COMP_LEN (16*1024)

TEST(diff_patch_no_comp)
{
    int rc;
    uint8_t *origin_data = create_origin_data(DIFF_PATCH_NO_COMP_LEN);
    uint8_t *new_data = create_new_data(DIFF_PATCH_NO_COMP_LEN, origin_data);
    uint8_t patch_buffer[32*1024]; // Hold the generated patch data
    uint8_t output[DIFF_PATCH_NO_COMP_LEN]; // Result from applying the patch
    struct bpak_bsdiff_context bsdiff;
    struct bpak_bspatch_context bspatch;
    struct bspatch_priv priv;

    /* Generate un-compressed patch */
    printf("Generating patch\n");
    patch_length = 0;

    rc = bpak_bsdiff_init(&bsdiff, origin_data, DIFF_PATCH_NO_COMP_LEN,
                                new_data, DIFF_PATCH_NO_COMP_LEN,
                                write_patch_output, 0,
                                BPAK_COMPRESSION_NONE,
                                (void *) patch_buffer);
    ASSERT(rc == 0);

    rc = bpak_bsdiff(&bsdiff);
    ASSERT(rc > 0);

    bpak_bsdiff_free(&bsdiff);

    /* Apply patch */

    printf("Applying patch, length = %zu\n", patch_length);
    priv.origin_data = origin_data;
    priv.origin_length = DIFF_PATCH_NO_COMP_LEN;
    priv.output_data = output;
    priv.output_length = DIFF_PATCH_NO_COMP_LEN;

    rc = bpak_bspatch_init(&bspatch,
                           8192,
                           patch_length,
                           read_origin, 0,
                           write_output, 0,
                           BPAK_COMPRESSION_NONE,
                           &priv);
    ASSERT_EQ(rc, 0);

    rc = bpak_bspatch_write(&bspatch, patch_buffer, patch_length);
    ASSERT_EQ(rc, 0);

    ssize_t output_length = bpak_bspatch_final(&bspatch);
    printf("Patch output length: %li\n", output_length);
    ASSERT(output_length > 0);

    bpak_bspatch_free(&bspatch);

    ASSERT_MEMORY(output, new_data, DIFF_PATCH_NO_COMP_LEN);

    free(new_data);
    free(origin_data);
}
