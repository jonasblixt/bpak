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

static void test_patch_file_diff2_hs(void **state)
{
    (void)state;
    check_patch_file(TEST_DATA("diff2_patch.bin"),
                     TEST_DATA("diff2_origin.bin"),
                     TEST_DATA("diff2_target.bin"),
                     BPAK_COMPRESSION_HS);
}

static void test_patch_file_diff2_no_comp(void **state)
{
    (void)state;
    check_patch_file(TEST_DATA("diff2_patch_no_comp.bin"),
                     TEST_DATA("diff2_origin.bin"),
                     TEST_DATA("diff2_target.bin"),
                     BPAK_COMPRESSION_NONE);
}

/*
 * Round trip through both bsdiff and bspatch:
 *
 * 1. Generate origin test data
 * 2. Generate 'new' data based on origin data
 * 3. Create patch
 * 4. Apply patch
 * 5. Verify result
 */
static void check_diff_patch(size_t length, enum bpak_compression compression)
{
    struct bpak_bsdiff_context bsdiff;
    uint8_t *origin = malloc(length);
    uint8_t *target = malloc(length);
    struct patch_buffer patch = {
        .capacity = 2 * length + 4096,
    };
    int rc;

    patch.data = malloc(patch.capacity);
    assert_non_null(origin);
    assert_non_null(target);
    assert_non_null(patch.data);

    for (size_t i = 0; i < length; i++)
        origin[i] = 33 + i % 200;

    memcpy(target, origin, length);
    /* Change some data */
    memcpy(&target[500], "HELLO BSPATCH", 13);
    /* Remove a block of data */
    memset(&target[2048], 0, 512);

    rc = bpak_bsdiff_init(&bsdiff,
                          origin,
                          length,
                          target,
                          length,
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
                                  length,
                                  compression);

    assert_memory_equal(output, target, length);

    free(output);
    free(patch.data);
    free(target);
    free(origin);
}

static void test_diff_patch_no_comp(void **state)
{
    (void)state;
    check_diff_patch(16 * 1024, BPAK_COMPRESSION_NONE);
}

static void test_diff_patch_hs(void **state)
{
    (void)state;
    check_diff_patch(64 * 1024, BPAK_COMPRESSION_HS);
}

static void test_diff_patch_lzma(void **state)
{
    (void)state;
    check_diff_patch(64 * 1024, BPAK_COMPRESSION_LZMA);
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
    const int64_t huge_diff[] = { INT64_MAX, 0, INT64_MAX };
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

    /* Seeking back to the start of the origin is valid */
    assert_int_equal(apply_ctrl(back_to_start, 6), 10);
    assert_memory_equal(checked_output, "01230123\0\0", 10);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_patch_file_diff1_hs),
        cmocka_unit_test(test_patch_file_diff2_hs),
        cmocka_unit_test(test_patch_file_diff2_no_comp),
        cmocka_unit_test(test_diff_patch_no_comp),
        cmocka_unit_test(test_diff_patch_hs),
        cmocka_unit_test(test_diff_patch_lzma),
        cmocka_unit_test(test_patch_bad_ctrl),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
