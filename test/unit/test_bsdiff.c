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

/* bspatch control data: sign and magnitude, little endian */
static void put_ctrl(uint8_t *buf, int64_t value)
{
    uint64_t magnitude = value < 0 ? -(uint64_t)value : (uint64_t)value;

    for (int i = 0; i < 8; i++)
        buf[i] = (magnitude >> (8 * i)) & 0xff;

    if (value < 0)
        buf[7] |= 0x80;
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

    /* diff, extra, adjust */
    put_ctrl(&patch[0], length);
    put_ctrl(&patch[8], extra_length);
    put_ctrl(&patch[16], 0);
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

static void test_diff_patch_lzma(void **state)
{
    (void)state;
    check_diff_patch(64 * 1024, 0, false, BPAK_COMPRESSION_LZMA);
}

/* An allocator that tags its allocations, freeing anything else fails */
#define ALLOC_TAG 0x62706b61u

static unsigned int tagged_allocations;

static void *tagged_calloc(size_t nmemb, size_t size)
{
    uint32_t *p = calloc(1, nmemb * size + 16);

    assert_non_null(p);
    *p = ALLOC_TAG;
    tagged_allocations++;
    return (uint8_t *)p + 16;
}

static void tagged_free(void *ptr)
{
    if (ptr == NULL)
        return;

    uint32_t *p = (uint32_t *)((uint8_t *)ptr - 16);

    assert_int_equal(*p, ALLOC_TAG);
    assert_true(tagged_allocations > 0);
    tagged_allocations--;
    *p = 0;
    free(p);
}

static void test_lzma_allocator(void **state)
{
    (void)state;

    tagged_allocations = 0;
    assert_int_equal(bpak_set_calloc_free(tagged_calloc, tagged_free), BPAK_OK);

    /* liblzma allocates with the allocator of the stream when it is
     * initialized */
    check_diff_patch(64 * 1024, 0, false, BPAK_COMPRESSION_LZMA);

    assert_int_equal(bpak_set_calloc_free(calloc, free), BPAK_OK);
    assert_int_equal(tagged_allocations, 0);
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
        put_ctrl(&patch[patch_length], ctrl[i]);
        put_ctrl(&patch[patch_length + 8], ctrl[i + 1]);
        put_ctrl(&patch[patch_length + 16], ctrl[i + 2]);
        patch_length += BPAK_BSPATCH_CTRL_BUFFER_LENGTH;

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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_patch_file_diff1_hs),
        cmocka_unit_test(test_patch_no_comp),
        cmocka_unit_test(test_diff_patch_no_comp),
        cmocka_unit_test(test_diff_patch_hs),
        cmocka_unit_test(test_diff_patch_hs_random),
        cmocka_unit_test(test_diff_patch_lzma),
        cmocka_unit_test(test_patch_bad_ctrl),
        cmocka_unit_test(test_lzma_allocator),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
