#include <string.h>
#include <bpak/bpak.h>
#include <bpak/id.h>
#include <bpak/merkle.h>
#include <bpak/transport.h>
#include <bpak/utils.h>
#include "test_helpers.h"

#define HEADER_SIZE sizeof(struct bpak_header)
#define PART_SIZE   512

/* Packages in memory: the header followed by the part data. The arrays are
 * larger than the packages, the callbacks fail the test on accesses outside
 * of the parts the decoder works on. */
static uint8_t output[HEADER_SIZE + 3 * 4096];
static uint8_t origin[HEADER_SIZE + 4096];
static uint64_t output_limit;
static uint64_t origin_limit;

static const uint8_t uuid[16] = { 0x08, 0x88, 0xb0, 0xfa, 0x9c, 0x48,
                                  0x45, 0x24, 0x98, 0x45, 0x06, 0xa6,
                                  0x41, 0xb6, 0x1e, 0xdd };

static ssize_t write_output(off_t offset, uint8_t *buffer, size_t length,
                            void *user)
{
    (void)user;
    assert_true(offset >= (off_t)HEADER_SIZE);
    assert_true(offset + length <= output_limit);
    memcpy(&output[offset], buffer, length);
    return length;
}

static ssize_t read_output(off_t offset, uint8_t *buffer, size_t length,
                           void *user)
{
    (void)user;
    assert_true(offset >= (off_t)HEADER_SIZE);
    assert_true(offset + length <= sizeof(output));
    memcpy(buffer, &output[offset], length);
    return length;
}

static ssize_t write_output_header(off_t offset, uint8_t *buffer, size_t length,
                                   void *user)
{
    (void)user;
    (void)offset;
    assert_int_equal(length, HEADER_SIZE);
    memcpy(output, buffer, length);
    return length;
}

static ssize_t read_origin(off_t offset, uint8_t *buffer, size_t length,
                           void *user)
{
    (void)user;
    assert_true(offset >= (off_t)HEADER_SIZE);
    assert_true(offset + length <= origin_limit);
    memcpy(buffer, &origin[offset], length);
    return length;
}

static void init_package(struct bpak_header *h)
{
    bpak_init_header(h);
    test_add_meta_value(h, BPAK_ID_BPAK_PACKAGE, 0, uuid, sizeof(uuid));
}

/* Decode a one part patch of 'patch_length' bytes against an origin part of
 * PART_SIZE bytes */
static int decode_patch_with(uint32_t decoder_id, uint8_t *patch,
                             size_t patch_length, uint64_t part_size)
{
    struct bpak_header patch_header;
    struct bpak_header origin_header;
    struct bpak_transport_decode ctx;
    uint8_t buffer[BPAK_CHUNK_BUFFER_LENGTH];
    struct bpak_part_header *part;
    int rc;

    init_package(&origin_header);
    test_add_part_with_size(&origin_header, "fs", PART_SIZE);

    init_package(&patch_header);
    part = test_add_part_with_size(&patch_header, "fs", part_size);
    part->flags = BPAK_FLAG_TRANSPORT;
    part->transport_size = patch_length;
    rc = bpak_add_transport_meta(&patch_header,
                                 part->id,
                                 BPAK_ID_BSDIFF_NO_COMP,
                                 decoder_id);
    assert_int_equal(rc, BPAK_OK);

    memset(output, 0, sizeof(output));
    for (size_t i = 0; i < sizeof(origin); i++)
        origin[i] = i & 0xff;

    output_limit = HEADER_SIZE + part_size;
    origin_limit = HEADER_SIZE + PART_SIZE;

    rc = bpak_transport_decode_init(&ctx,
                                    buffer,
                                    sizeof(buffer),
                                    &patch_header,
                                    write_output,
                                    read_output,
                                    HEADER_SIZE,
                                    write_output_header,
                                    NULL);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_set_origin(&ctx,
                                          &origin_header,
                                          read_origin,
                                          HEADER_SIZE);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_start(&ctx, part);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_write_chunk(&ctx, patch, patch_length);

    if (rc == BPAK_OK)
        rc = bpak_transport_decode_finish(&ctx);

    bpak_transport_decode_free(&ctx);
    return rc;
}

static int decode_patch(uint8_t *patch, size_t patch_length, uint64_t part_size)
{
    return decode_patch_with(BPAK_ID_BSPATCH_NO_COMP,
                             patch,
                             patch_length,
                             part_size);
}

/* The decoder state is freed when decoding stops in the middle of a part,
 * LeakSanitizer reports the lzma decoder otherwise */
static void test_patch_error_frees_decoder(void **state)
{
    (void)state;
    uint8_t patch[64];

    memset(patch, 0xa5, sizeof(patch));

    assert_int_equal(decode_patch_with(BPAK_ID_BSPATCH_LZMA,
                                       patch,
                                       sizeof(patch),
                                       PART_SIZE),
                     -BPAK_DECOMPRESSOR_ERROR);
}

static void test_patch(void **state)
{
    (void)state;
    uint8_t patch[24 + PART_SIZE] = { 0 };
    size_t length = test_put_ctrl_triple(patch, PART_SIZE, 0, 0);

    /* Zero diff bytes, the output is the origin part */
    assert_int_equal(decode_patch(patch, length + PART_SIZE, PART_SIZE),
                     BPAK_OK);
    assert_memory_equal(&output[HEADER_SIZE], &origin[HEADER_SIZE], PART_SIZE);
}

static void test_patch_writes_outside_part(void **state)
{
    (void)state;
    uint8_t patch[24 + 2 * PART_SIZE] = { 0 };
    size_t length = test_put_ctrl_triple(patch, 0, 2 * PART_SIZE, 0);

    assert_int_equal(decode_patch(patch, length + 2 * PART_SIZE, PART_SIZE),
                     -BPAK_PATCH_WRITE_ERROR);
}

static void test_patch_reads_outside_origin(void **state)
{
    (void)state;
    uint8_t patch[24 + 2 * PART_SIZE] = { 0 };
    size_t length = test_put_ctrl_triple(patch, 2 * PART_SIZE, 0, 0);

    /* The output part is large enough, the origin part is not */
    assert_int_equal(decode_patch(patch, length + 2 * PART_SIZE, 2 * PART_SIZE),
                     -BPAK_PATCH_READ_ORIGIN_ERROR);

    /* Seek past the end of the origin part */
    length = test_put_ctrl_triple(patch, 0, 0, PART_SIZE);
    length += test_put_ctrl_triple(&patch[length], 1, 0, 0);
    assert_int_equal(decode_patch(patch, length + 1, PART_SIZE),
                     -BPAK_PATCH_READ_ORIGIN_ERROR);
}

static void test_copy_too_much(void **state)
{
    (void)state;
    struct bpak_header h;
    struct bpak_transport_decode ctx;
    uint8_t buffer[BPAK_CHUNK_BUFFER_LENGTH];
    uint8_t data[2 * PART_SIZE] = { 0 };
    struct bpak_part_header *part;
    int rc;

    init_package(&h);
    part = test_add_part_with_size(&h, "fs", PART_SIZE);
    output_limit = HEADER_SIZE + PART_SIZE;

    rc = bpak_transport_decode_init(&ctx,
                                    buffer,
                                    sizeof(buffer),
                                    &h,
                                    write_output,
                                    read_output,
                                    HEADER_SIZE,
                                    write_output_header,
                                    NULL);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_start(&ctx, part);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_write_chunk(&ctx, data, PART_SIZE);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_write_chunk(&ctx, data, 1);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
}

/* Generate the hash tree of a 4096 byte part when it is decoded */
static int decode_merkle(uint64_t tree_size, uint16_t salt_size, bool root_hash)
{
    struct bpak_header h;
    struct bpak_transport_decode ctx;
    uint8_t buffer[BPAK_CHUNK_BUFFER_LENGTH];
    struct bpak_part_header *fs;
    struct bpak_part_header *tree;
    struct bpak_meta_header *meta;
    int rc;

    init_package(&h);
    fs = test_add_part_with_size(&h, "fs", 4096);
    tree = test_add_part_with_size(&h, "fs-hash-tree", tree_size);
    tree->flags = BPAK_FLAG_TRANSPORT;

    rc = bpak_add_meta(&h, BPAK_ID_MERKLE_SALT, fs->id, salt_size, &meta);
    assert_int_equal(rc, BPAK_OK);

    /* A zero root hash, which does not match */
    if (root_hash) {
        rc = bpak_add_meta(&h, BPAK_ID_MERKLE_ROOT_HASH, fs->id, 32, &meta);
        assert_int_equal(rc, BPAK_OK);
    }

    rc = bpak_add_transport_meta(&h,
                                 tree->id,
                                 BPAK_ID_MERKLE_GENERATE,
                                 BPAK_ID_MERKLE_GENERATE);
    assert_int_equal(rc, BPAK_OK);

    memset(output, 0x55, sizeof(output));
    output_limit = HEADER_SIZE + 4096 + tree_size;

    rc = bpak_transport_decode_init(&ctx,
                                    buffer,
                                    sizeof(buffer),
                                    &h,
                                    write_output,
                                    read_output,
                                    HEADER_SIZE,
                                    write_output_header,
                                    NULL);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_start(&ctx, tree);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_transport_decode_finish(&ctx);
    bpak_transport_decode_free(&ctx);
    return rc;
}

static void test_merkle_tree_too_small(void **state)
{
    (void)state;

    /* The computed tree does not fit the tree part */
    assert_true(bpak_merkle_compute_size(4096) > PART_SIZE);
    assert_int_equal(decode_merkle(PART_SIZE, 32, true), -BPAK_SIZE_ERROR);
}

static void test_merkle_bad_meta(void **state)
{
    (void)state;
    uint64_t tree_size = bpak_merkle_compute_size(4096);

    assert_int_equal(decode_merkle(tree_size, 16, true), -BPAK_SIZE_ERROR);
    assert_int_equal(decode_merkle(tree_size, 32, false),
                     -BPAK_MISSING_META_DATA);
    assert_int_equal(decode_merkle(tree_size, 32, true), -BPAK_BAD_ROOT_HASH);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_patch),
        cmocka_unit_test(test_patch_writes_outside_part),
        cmocka_unit_test(test_patch_error_frees_decoder),
        cmocka_unit_test(test_patch_reads_outside_origin),
        cmocka_unit_test(test_copy_too_much),
        cmocka_unit_test(test_merkle_tree_too_small),
        cmocka_unit_test(test_merkle_bad_meta),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
