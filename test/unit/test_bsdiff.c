#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/bspatch.h>
#include <bpak/bsdiff.h>
#include "test_helpers.h"

struct bspatch_priv {
    uint8_t *origin_data;
    size_t origin_length;
    uint8_t *output_data;
    size_t output_length;
};

static ssize_t read_origin(off_t offset, uint8_t *buffer, size_t length,
                           void *user_priv)
{
    struct bspatch_priv *priv = (struct bspatch_priv *)user_priv;

    ssize_t bytes_to_read = ((offset + length) > priv->origin_length)
                                ? (ssize_t)(priv->origin_length - offset)
                                : (ssize_t)length;

    if (bytes_to_read > 0) {
        memcpy(buffer, &priv->origin_data[offset], bytes_to_read);
    }

    return bytes_to_read;
}

static ssize_t write_output(off_t offset, uint8_t *buffer, size_t length,
                            void *user_priv)
{
    struct bspatch_priv *priv = (struct bspatch_priv *)user_priv;

    ssize_t bytes_to_write = ((offset + length) > priv->output_length)
                                 ? (ssize_t)(priv->output_length - offset)
                                 : (ssize_t)length;

    if (bytes_to_write > 0) {
        memcpy(&priv->output_data[offset], buffer, bytes_to_write);
    }

    return bytes_to_write;
}

struct patch_buffer {
    uint8_t *data;
    size_t capacity;
    size_t length;
};

static ssize_t write_patch_output(off_t offset, uint8_t *buffer, size_t length,
                                  void *user_priv)
{
    struct patch_buffer *patch = (struct patch_buffer *)user_priv;

    assert_true(offset + length <= patch->capacity);
    memcpy(&patch->data[offset], buffer, length);
    patch->length += length;
    return length;
}

/* Apply 'patch' to 'origin' and return the malloc'd result */
static uint8_t *apply_patch(const uint8_t *patch, size_t patch_length,
                            uint8_t *origin, size_t origin_length,
                            size_t output_capacity,
                            enum bpak_compression compression)
{
    struct bpak_bspatch_context bspatch;
    uint8_t decode_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    struct bspatch_priv priv = {
        .origin_data = origin,
        .origin_length = origin_length,
        .output_data = calloc(1, output_capacity),
        .output_length = output_capacity,
    };
    int rc;

    assert_non_null(priv.output_data);

    rc = bpak_bspatch_init(&bspatch,
                           decode_buffer,
                           sizeof(decode_buffer),
                           patch_length,
                           read_origin,
                           0,
                           write_output,
                           0,
                           compression,
                           &priv);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_bspatch_write(&bspatch, (uint8_t *)patch, patch_length);
    assert_int_equal(rc, BPAK_OK);

    ssize_t output_length = bpak_bspatch_final(&bspatch);
    assert_true(output_length > 0);

    bpak_bspatch_free(&bspatch);
    return priv.output_data;
}

/*
 * Apply a pre-generated patch from test/data and compare the result with
 * the expected target.
 */
static void check_patch_file(const char *patch_fn, const char *origin_fn,
                             const char *target_fn,
                             enum bpak_compression compression)
{
    uint8_t *patch, *origin, *target;
    size_t patch_length = test_load_file(patch_fn, &patch);
    size_t origin_length = test_load_file(origin_fn, &origin);
    size_t target_length = test_load_file(target_fn, &target);

    uint8_t *output = apply_patch(patch,
                                  patch_length,
                                  origin,
                                  origin_length,
                                  2 * 1024 * 1024,
                                  compression);

    assert_memory_equal(output, target, target_length);

    free(output);
    free(patch);
    free(origin);
    free(target);
}

static void test_patch_file_diff1_hs(void **state)
{
    (void)state;
    check_patch_file(TEST_DATA("diff1_patch.bin"),
                     TEST_DATA("diff1_origin.txt"),
                     TEST_DATA("diff1_new.txt"),
                     BPAK_COMPRESSION_HS);
}

/* Pseudo-random data that is the same in every run, xorshift32 */
static void fill_random(uint8_t *buffer, size_t length, uint32_t seed)
{
    uint32_t x = seed;

    for (size_t i = 0; i < length; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buffer[i] = x & 0xff;
    }
}

/*
 * Round trip through both bsdiff and bspatch:
 *
 * 1. Generate origin test data, a repeating pattern or pseudo-random data
 * 2. Generate 'new' data based on origin data, with 'extra_length' bytes
 *    of pseudo-random data appended
 * 3. Create patch
 * 4. Apply patch
 * 5. Verify result
 */
static void check_diff_patch(size_t length, size_t extra_length,
                             bool random_origin,
                             enum bpak_compression compression)
{
    struct bpak_bsdiff_context bsdiff;
    size_t target_length = length + extra_length;
    uint8_t *origin = malloc(length);
    uint8_t *target = malloc(target_length);
    struct patch_buffer patch = {
        .capacity = 2 * target_length + 4096,
    };
    int rc;

    patch.data = malloc(patch.capacity);
    assert_non_null(origin);
    assert_non_null(target);
    assert_non_null(patch.data);

    if (random_origin) {
        fill_random(origin, length, 1);
    } else {
        for (size_t i = 0; i < length; i++)
            origin[i] = 33 + i % 200;
    }

    memcpy(target, origin, length);
    /* Change some data */
    memcpy(&target[500], "HELLO BSPATCH", 13);
    /* Remove a block of data */
    memset(&target[2048], 0, 512);
    /* Add new data */
    fill_random(&target[length], extra_length, 2);

    rc = bpak_bsdiff_init(&bsdiff,
                          origin,
                          length,
                          target,
                          target_length,
                          write_patch_output,
                          0,
                          compression,
                          &patch);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_bsdiff(&bsdiff);
    assert_true(rc > 0);

    bpak_bsdiff_free(&bsdiff);

    uint8_t *output = apply_patch(patch.data,
                                  patch.length,
                                  origin,
                                  length,
                                  target_length,
                                  compression);

    assert_memory_equal(output, target, target_length);

    free(output);
    free(patch.data);
    free(target);
    free(origin);
}

static void test_diff_patch_no_comp(void **state)
{
    (void)state;
    check_diff_patch(16 * 1024, 0, false, BPAK_COMPRESSION_NONE);
}

static void test_diff_patch_hs(void **state)
{
    (void)state;
    check_diff_patch(64 * 1024, 0, false, BPAK_COMPRESSION_HS);
}

/* Pseudo-random data does not compress, larger than the buffers of the
 * compressor and the patch */
static void test_diff_patch_hs_random(void **state)
{
    (void)state;
    check_diff_patch(256 * 1024, 128 * 1024, true, BPAK_COMPRESSION_HS);
}

/* A patch that copies the origin, all diff bytes are zero, and appends
 * the extra bytes */
static void test_patch_no_comp(void **state)
{
    (void)state;
    const size_t length = 256 * 1024;
    const size_t extra_length = 128 * 1024;
    const size_t patch_length =
        BPAK_BSPATCH_CTRL_BUFFER_LENGTH + length + extra_length;
    uint8_t *origin = malloc(length);
    uint8_t *patch = calloc(1, patch_length);
    uint8_t *extra = &patch[BPAK_BSPATCH_CTRL_BUFFER_LENGTH + length];

    assert_non_null(origin);
    assert_non_null(patch);
    fill_random(origin, length, 1);

    test_put_ctrl_triple(patch, length, extra_length, 0);
    fill_random(extra, extra_length, 2);

    uint8_t *output = apply_patch(patch,
                                  patch_length,
                                  origin,
                                  length,
                                  length + extra_length,
                                  BPAK_COMPRESSION_NONE);

    assert_memory_equal(output, origin, length);
    assert_memory_equal(&output[length], extra, extra_length);

    free(output);
    free(patch);
    free(origin);
}

static void test_lzma_allocator(void **state)
{
    (void)state;

    test_tagged_allocator_begin();

    /* liblzma allocates with the allocator of the stream when it is
     * initialized */
    check_diff_patch(64 * 1024, 0, false, BPAK_COMPRESSION_LZMA);

    assert_int_equal(test_tagged_allocator_end(), 0);
}

static uint8_t checked_origin[16] = "0123456789abcdef";
static uint8_t checked_output[64];

/* Fail the test on lengths larger than the bspatch buffers */
static ssize_t checked_read_origin(off_t offset, uint8_t *buffer, size_t length,
                                   void *user_priv)
{
    (void)user_priv;
    assert_true(offset >= 0);
    assert_true(length <= BPAK_CHUNK_BUFFER_LENGTH / 2);

    if ((size_t)offset + length > sizeof(checked_origin))
        return -BPAK_READ_ERROR;

    memcpy(buffer, &checked_origin[offset], length);
    return length;
}

static ssize_t checked_write_output(off_t offset, uint8_t *buffer,
                                    size_t length, void *user_priv)
{
    (void)user_priv;
    assert_true(offset >= 0);
    assert_true(length <= BPAK_CHUNK_BUFFER_LENGTH);

    if ((size_t)offset + length > sizeof(checked_output))
        return -BPAK_WRITE_ERROR;

    memcpy(&checked_output[offset], buffer, length);
    return length;
}

static int apply_ctrl(const int64_t *ctrl, size_t n_ctrl)
{
    struct bpak_bspatch_context bspatch;
    uint8_t decode_buffer[BPAK_CHUNK_BUFFER_LENGTH];
    uint8_t patch[4 * BPAK_BSPATCH_CTRL_BUFFER_LENGTH + 64] = { 0 };
    size_t patch_length = 0;
    int rc;

    /* Control tuples followed by zeroed diff bytes and extra bytes */
    for (size_t i = 0; i < n_ctrl; i += 3) {
        patch_length += test_put_ctrl_triple(&patch[patch_length],
                                             ctrl[i],
                                             ctrl[i + 1],
                                             ctrl[i + 2]);

        for (int j = 0; j < 2; j++) {
            if (ctrl[i + j] > 0 && ctrl[i + j] < 16)
                patch_length += ctrl[i + j];
        }
    }

    memset(checked_output, 0, sizeof(checked_output));

    rc = bpak_bspatch_init(&bspatch,
                           decode_buffer,
                           sizeof(decode_buffer),
                           patch_length,
                           checked_read_origin,
                           0,
                           checked_write_output,
                           0,
                           BPAK_COMPRESSION_NONE,
                           NULL);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_bspatch_write(&bspatch, patch, patch_length);

    if (rc == BPAK_OK)
        rc = bpak_bspatch_final(&bspatch);

    bpak_bspatch_free(&bspatch);
    return rc;
}

static void test_patch_bad_ctrl(void **state)
{
    (void)state;

    /* diff, extra, adjust */
    const int64_t negative_diff[] = { -16, 0, 0 };
    const int64_t negative_extra[] = { 0, -16, 0 };
    const int64_t huge_diff[] = { (int64_t)1 << 40, 0, 0 };
    const int64_t overflow_diff[] = { 4, 0, 0, INT64_MAX, 0, 0 };
    const int64_t overflow_adjust[] = { 1, 0, INT64_MAX };
    const int64_t overflow_extra[] = { 1, INT64_MAX, 0 };
    const int64_t before_origin[] = { 0, 0, -1 };
    const int64_t before_origin_after_diff[] = { 4, 0, -5 };
    const int64_t back_to_start[] = { 4, 0, -4, 4, 2, 0 };

    assert_int_equal(apply_ctrl(negative_diff, 3), -BPAK_SIZE_ERROR);
    assert_int_equal(apply_ctrl(negative_extra, 3), -BPAK_SIZE_ERROR);
    assert_int_equal(apply_ctrl(before_origin, 3), -BPAK_SIZE_ERROR);
    assert_int_equal(apply_ctrl(before_origin_after_diff, 3), -BPAK_SIZE_ERROR);

    /* Runs out of patch data in the diff, which is not an error until the
     * caller compares the output size */
    assert_int_equal(apply_ctrl(huge_diff, 3), 0);

    /* The positions do not fit off_t */
    assert_int_equal(apply_ctrl(overflow_diff, 6), -BPAK_SIZE_ERROR);
    assert_int_equal(apply_ctrl(overflow_adjust, 3), -BPAK_SIZE_ERROR);
    assert_int_equal(apply_ctrl(overflow_extra, 3), -BPAK_SIZE_ERROR);

    /* Seeking back to the start of the origin is valid */
    assert_int_equal(apply_ctrl(back_to_start, 6), 10);
    assert_memory_equal(checked_output, "01230123\0\0", 10);
}

/* Chunked diff tests. The patches are applied with the regular bspatch, which
 * must not need to know that the patch was created in chunks. */

struct chunk_test_priv {
    uint8_t *origin_data;
    size_t origin_length;
    uint8_t *output_data;
    size_t output_length;
    uint8_t *patch_data;
    size_t patch_capacity;
    size_t patch_length;
};

static ssize_t chunk_test_read_origin(off_t offset, uint8_t *buffer,
                                      size_t length, void *user_priv)
{
    struct chunk_test_priv *priv = (struct chunk_test_priv *)user_priv;

    assert_true(offset >= 0);
    assert_true((size_t)offset + length <= priv->origin_length);
    memcpy(buffer, &priv->origin_data[offset], length);
    return length;
}

static ssize_t chunk_test_write_output(off_t offset, uint8_t *buffer,
                                       size_t length, void *user_priv)
{
    struct chunk_test_priv *priv = (struct chunk_test_priv *)user_priv;

    assert_true(offset >= 0);
    assert_true((size_t)offset + length <= priv->output_length);
    memcpy(&priv->output_data[offset], buffer, length);
    return length;
}

static ssize_t chunk_test_write_patch(off_t offset, uint8_t *buffer,
                                      size_t length, void *user_priv)
{
    struct chunk_test_priv *priv = (struct chunk_test_priv *)user_priv;

    assert_true((size_t)offset + length <= priv->patch_capacity);
    memcpy(&priv->patch_data[offset], buffer, length);
    priv->patch_length = offset + length;
    return length;
}

static uint32_t prng_state;

static uint8_t prng(void)
{
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    return prng_state & 0xff;
}

/* Data that compresses somewhat, like a binary, with repeated sequences */
static uint8_t *create_binary_data(size_t length)
{
    uint8_t *output = malloc(length);
    assert_true(output != NULL);

    for (size_t i = 0; i < length; i++) {
        if ((i > 64) && (prng() < 64))
            output[i] = output[i - 1 - (prng() % 64)];
        else
            output[i] = prng();
    }

    return output;
}

/* Copy origin to a new buffer with an insertion, a deletion and edits */
static uint8_t *create_modified_data(uint8_t *origin, size_t origin_length,
                                     size_t insert_length, size_t delete_length,
                                     size_t *new_length)
{
    size_t insert_at = origin_length / 3;
    size_t delete_at = (origin_length * 2) / 3;
    size_t length = origin_length + insert_length - delete_length;
    uint8_t *output = malloc(length);
    uint8_t *p = output;
    assert_true(output != NULL);

    memcpy(p, origin, insert_at);
    p += insert_at;

    for (size_t i = 0; i < insert_length; i++)
        *p++ = prng();

    memcpy(p, &origin[insert_at], delete_at - insert_at);
    p += delete_at - insert_at;
    memcpy(p,
           &origin[delete_at + delete_length],
           origin_length - delete_at - delete_length);

    for (size_t i = 0; i < 100; i++)
        output[prng_state % length] ^= 0x55;

    *new_length = length;
    return output;
}

static size_t threaded_diff_patch(uint8_t *origin, size_t origin_length,
                                  uint8_t *target, size_t target_length,
                                  enum bpak_compression compression,
                                  size_t chunk_size, size_t window_margin,
                                  unsigned int threads, size_t segment_size,
                                  uint8_t **patch_out)
{
    int rc;
    struct bpak_bsdiff_context bsdiff;
    struct bpak_bspatch_context bspatch;
    struct chunk_test_priv priv;
    uint8_t decode_buffer[BPAK_CHUNK_BUFFER_LENGTH];

    memset(&priv, 0, sizeof(priv));
    priv.origin_data = origin;
    priv.origin_length = origin_length;
    priv.output_data = malloc(target_length);
    priv.output_length = target_length;
    priv.patch_capacity = target_length * 2 + 64 * 1024;
    priv.patch_data = malloc(priv.patch_capacity);
    assert_true(priv.output_data != NULL);
    assert_true(priv.patch_data != NULL);

    rc = bpak_bsdiff_init(&bsdiff,
                          origin,
                          origin_length,
                          target,
                          target_length,
                          chunk_test_write_patch,
                          0,
                          compression,
                          &priv);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_bsdiff_set_chunking(&bsdiff, chunk_size, window_margin);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_bsdiff_set_threads(&bsdiff, threads, segment_size);
    assert_int_equal(rc, BPAK_OK);

    ssize_t patch_length = bpak_bsdiff(&bsdiff);
    assert_true(patch_length > 0);
    assert_int_equal((size_t)patch_length, priv.patch_length);
    bpak_bsdiff_free(&bsdiff);

    printf("Chunked patch: chunk %zu, margin %zu, compression %i: %zi bytes\n",
           chunk_size,
           window_margin,
           compression,
           patch_length);

    rc = bpak_bspatch_init(&bspatch,
                           decode_buffer,
                           sizeof(decode_buffer),
                           patch_length,
                           chunk_test_read_origin,
                           0,
                           chunk_test_write_output,
                           0,
                           compression,
                           &priv);
    assert_int_equal(rc, BPAK_OK);

    /* Feed the patch in pieces, like a device receiving it would */
    for (ssize_t pos = 0; pos < patch_length; pos += 4096) {
        rc = bpak_bspatch_write(&bspatch,
                                &priv.patch_data[pos],
                                BPAK_MIN(4096, patch_length - pos));
        assert_int_equal(rc, BPAK_OK);
    }

    ssize_t output_length = bpak_bspatch_final(&bspatch);
    bpak_bspatch_free(&bspatch);

    assert_int_equal((size_t)output_length, target_length);
    assert_memory_equal(priv.output_data, target, target_length);

    free(priv.output_data);

    if (patch_out != NULL)
        *patch_out = priv.patch_data;
    else
        free(priv.patch_data);

    return patch_length;
}

static size_t chunked_diff_patch(uint8_t *origin, size_t origin_length,
                                 uint8_t *target, size_t target_length,
                                 enum bpak_compression compression,
                                 size_t chunk_size, size_t window_margin,
                                 uint8_t **patch_out)
{
    return threaded_diff_patch(origin,
                               origin_length,
                               target,
                               target_length,
                               compression,
                               chunk_size,
                               window_margin,
                               1,
                               0,
                               patch_out);
}

#define CHUNK_TEST_LEN    (512 * 1024)
#define CHUNK_TEST_CHUNK  (64 * 1024)
#define CHUNK_TEST_MARGIN (16 * 1024)

static void chunked_test(enum bpak_compression compression,
                         size_t insert_length, size_t delete_length,
                         bool tiny_chunks)
{
    size_t new_length;

    prng_state = 0x12345678;
    uint8_t *origin = create_binary_data(CHUNK_TEST_LEN);
    uint8_t *target = create_modified_data(origin,
                                           CHUNK_TEST_LEN,
                                           insert_length,
                                           delete_length,
                                           &new_length);

    size_t unchunked = chunked_diff_patch(origin,
                                          CHUNK_TEST_LEN,
                                          target,
                                          new_length,
                                          compression,
                                          0,
                                          0,
                                          NULL);
    size_t chunked = chunked_diff_patch(origin,
                                        CHUNK_TEST_LEN,
                                        target,
                                        new_length,
                                        compression,
                                        CHUNK_TEST_CHUNK,
                                        CHUNK_TEST_MARGIN,
                                        NULL);
    /* A chunk size that does not divide the target, without margin */
    chunked_diff_patch(origin,
                       CHUNK_TEST_LEN,
                       target,
                       new_length,
                       compression,
                       100 * 1000,
                       0,
                       NULL);

    if (tiny_chunks) {
        chunked_diff_patch(origin,
                           CHUNK_TEST_LEN,
                           target,
                           new_length,
                           compression,
                           1000,
                           100,
                           NULL);
    }

    /* Data that moved less than the margin is still found since the window
     * follows the data. Data that moved further is not, the patch is still
     * correct but larger. */
    if ((insert_length < CHUNK_TEST_MARGIN) &&
        (delete_length < CHUNK_TEST_MARGIN)) {
        assert_true(chunked < unchunked + unchunked / 20 + 256);
    }

    free(target);
    free(origin);
}

static void test_diff_patch_chunked_no_comp(void **state)
{
    (void)state;
    chunked_test(BPAK_COMPRESSION_NONE, 10000, 5000, true);
}

static void test_diff_patch_chunked_hs(void **state)
{
    (void)state;
    chunked_test(BPAK_COMPRESSION_HS, 10000, 5000, false);
}

static void test_diff_patch_chunked_lzma(void **state)
{
    (void)state;
    chunked_test(BPAK_COMPRESSION_LZMA, 10000, 5000, false);
}

static void test_diff_patch_chunked_grow_beyond_margin(void **state)
{
    (void)state;
    chunked_test(BPAK_COMPRESSION_HS, 4 * CHUNK_TEST_MARGIN, 0, false);
}

static void test_diff_patch_chunked_shrink_beyond_margin(void **state)
{
    (void)state;
    chunked_test(BPAK_COMPRESSION_HS, 0, 4 * CHUNK_TEST_MARGIN, false);
}

static void test_diff_patch_chunked_small_origin(void **state)
{
    (void)state;
    /* Origin smaller than the window, target much larger */
    prng_state = 0xcafe;
    uint8_t *origin = create_binary_data(10000);
    uint8_t *target = create_binary_data(300000);

    memcpy(&target[1000], origin, 10000);
    memcpy(&target[250000], origin, 10000);

    chunked_diff_patch(origin,
                       10000,
                       target,
                       300000,
                       BPAK_COMPRESSION_HS,
                       64 * 1024,
                       16 * 1024,
                       NULL);

    free(target);
    free(origin);
}

static void test_diff_patch_chunk_larger_than_target(void **state)
{
    (void)state;
    /* A chunk size larger than the target is the same as no chunking */
    uint8_t *patch_unchunked;
    uint8_t *patch_chunked;
    size_t new_length;

    prng_state = 0xbeef;
    uint8_t *origin = create_binary_data(CHUNK_TEST_LEN);
    uint8_t *target =
        create_modified_data(origin, CHUNK_TEST_LEN, 1000, 1000, &new_length);

    size_t unchunked_length = chunked_diff_patch(origin,
                                                 CHUNK_TEST_LEN,
                                                 target,
                                                 new_length,
                                                 BPAK_COMPRESSION_NONE,
                                                 0,
                                                 0,
                                                 &patch_unchunked);
    size_t chunked_length = chunked_diff_patch(origin,
                                               CHUNK_TEST_LEN,
                                               target,
                                               new_length,
                                               BPAK_COMPRESSION_NONE,
                                               4 * CHUNK_TEST_LEN,
                                               1024,
                                               &patch_chunked);

    assert_int_equal(unchunked_length, chunked_length);
    assert_memory_equal(patch_unchunked, patch_chunked, unchunked_length);

    free(patch_chunked);
    free(patch_unchunked);
    free(target);
    free(origin);
}

/* Segments of the target are diffed by threads. The patch only depends on
 * the segment size, not on the number of threads. */
static void threaded_test(enum bpak_compression compression, size_t chunk_size,
                          size_t window_margin)
{
    uint8_t *patch_single;
    uint8_t *patch_threads;
    size_t new_length;

    prng_state = 0x5eed;
    uint8_t *origin = create_binary_data(CHUNK_TEST_LEN);
    uint8_t *target =
        create_modified_data(origin, CHUNK_TEST_LEN, 10000, 5000, &new_length);

    size_t unsegmented = threaded_diff_patch(origin,
                                             CHUNK_TEST_LEN,
                                             target,
                                             new_length,
                                             compression,
                                             chunk_size,
                                             window_margin,
                                             1,
                                             0,
                                             NULL);
    size_t single_length = threaded_diff_patch(origin,
                                               CHUNK_TEST_LEN,
                                               target,
                                               new_length,
                                               compression,
                                               chunk_size,
                                               window_margin,
                                               1,
                                               16 * 1024,
                                               &patch_single);

    for (unsigned int threads = 2; threads <= 8; threads *= 2) {
        size_t threads_length = threaded_diff_patch(origin,
                                                    CHUNK_TEST_LEN,
                                                    target,
                                                    new_length,
                                                    compression,
                                                    chunk_size,
                                                    window_margin,
                                                    threads,
                                                    16 * 1024,
                                                    &patch_threads);

        assert_int_equal(threads_length, single_length);
        assert_memory_equal(patch_threads, patch_single, single_length);
        free(patch_threads);
    }

    /* Every segment boundary costs a few bytes */
    assert_true(single_length < unsegmented + unsegmented / 50 + 1024);

    free(patch_single);
    free(target);
    free(origin);
}

static void test_diff_patch_threads_no_comp(void **state)
{
    (void)state;
    threaded_test(BPAK_COMPRESSION_NONE, 0, 0);
}

static void test_diff_patch_threads_hs(void **state)
{
    (void)state;
    threaded_test(BPAK_COMPRESSION_HS, 0, 0);
}

static void test_diff_patch_threads_lzma(void **state)
{
    (void)state;
    threaded_test(BPAK_COMPRESSION_LZMA, 0, 0);
}

/* Segments within chunks, the last chunk is not a multiple of the segment
 * size */
static void test_diff_patch_threads_chunked(void **state)
{
    (void)state;
    threaded_test(BPAK_COMPRESSION_HS, 100 * 1000, 16 * 1024);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_patch_file_diff1_hs),
        cmocka_unit_test(test_patch_no_comp),
        cmocka_unit_test(test_diff_patch_no_comp),
        cmocka_unit_test(test_diff_patch_hs),
        cmocka_unit_test(test_diff_patch_hs_random),
        cmocka_unit_test(test_patch_bad_ctrl),
        cmocka_unit_test(test_lzma_allocator),
        cmocka_unit_test(test_diff_patch_chunked_no_comp),
        cmocka_unit_test(test_diff_patch_chunked_hs),
        cmocka_unit_test(test_diff_patch_chunked_lzma),
        cmocka_unit_test(test_diff_patch_chunked_grow_beyond_margin),
        cmocka_unit_test(test_diff_patch_chunked_shrink_beyond_margin),
        cmocka_unit_test(test_diff_patch_chunked_small_origin),
        cmocka_unit_test(test_diff_patch_chunk_larger_than_target),
        cmocka_unit_test(test_diff_patch_threads_no_comp),
        cmocka_unit_test(test_diff_patch_threads_hs),
        cmocka_unit_test(test_diff_patch_threads_lzma),
        cmocka_unit_test(test_diff_patch_threads_chunked),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
