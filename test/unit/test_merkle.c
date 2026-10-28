#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/merkle.h>
#include "test_helpers.h"

/*
 * Reference root hashes were produced with veritysetup, for example:
 *
 * $ veritysetup format data.bin hashtree.bin -s <salt>
 * Hash type:              1
 * Data block size:        4096
 * Hash block size:        4096
 * Hash algorithm:         sha256
 * Salt: 65498d387f3c28382752721c5a4e5a551c1b3370b7967458de7c7c4f2cd2e97a
 */

static const uint8_t salt[] = {0x65, 0x49, 0x8d, 0x38, 0x7f, 0x3c, 0x28, 0x38,
                               0x27, 0x52, 0x72, 0x1c, 0x5a, 0x4e, 0x5a, 0x55,
                               0x1c, 0x1b, 0x33, 0x70, 0xb7, 0x96, 0x74, 0x58,
                               0xde, 0x7c, 0x7c, 0x4f, 0x2c, 0xd2, 0xe9, 0x7a};

static ssize_t merkle_wr(off_t offset, uint8_t *buf, size_t size, void *priv)
{
    uint8_t *data = (uint8_t *)priv;
    memcpy(&data[offset], buf, size);
    return size;
}

static ssize_t merkle_rd(off_t offset, uint8_t *buf, size_t size, void *priv)
{
    uint8_t *data = (uint8_t *)priv + offset;
    memcpy(buf, data, size);
    return size;
}

static void test_merkle_tree_sizes(void **state)
{
    (void)state;
    ssize_t merkle_sz = 0;

    merkle_sz = bpak_merkle_compute_size(1024 * 4 * 2);
    assert_int_equal(merkle_sz, 4096);

    merkle_sz = bpak_merkle_compute_size(1024 * 4);
    assert_int_equal(merkle_sz, 4096);

    merkle_sz = bpak_merkle_compute_size(16);
    assert_int_equal(merkle_sz, -BPAK_BAD_ALIGNMENT);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024);
    assert_int_equal(merkle_sz, 8458240);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 2l);
    assert_int_equal(merkle_sz, 16912384);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 1024l);
    assert_int_equal(merkle_sz, 8657571840);

    /* 1 TiB is the largest supported input data  with four levels */
    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 1024l + 4096);
    assert_int_equal(merkle_sz, -BPAK_NO_SPACE_LEFT);
}

/*
 * Build a merkle tree over 'data_size' bytes of a repeating pattern and
 * compare the root hash with 'expected_root_hash'.
 *
 * When 'unaligned' is set the data is fed in chunks of varying, non block
 * aligned, sizes to exercise the chunk buffering in bpak_merkle_write_chunk.
 */
static void check_merkle(size_t data_size, bool unaligned,
                         const char *expected_root_hash)
{
    int rc;
    struct bpak_merkle_context ctx;
    uint8_t *input_data = malloc(data_size);
    ssize_t merkle_sz = bpak_merkle_compute_size(data_size);
    assert_true(merkle_sz > 0);
    uint8_t *merkle_buf = calloc(1, merkle_sz);

    assert_non_null(input_data);
    assert_non_null(merkle_buf);
    memset(&ctx, 0, sizeof(ctx));

    for (size_t i = 0; i < data_size; i += 16)
        memcpy(&input_data[i], "0123456789abcdef", 16);

    rc = bpak_merkle_init(&ctx,
                          data_size,
                          salt,
                          sizeof(salt),
                          merkle_wr,
                          merkle_rd,
                          0,
                          true,
                          merkle_buf);
    assert_int_equal(rc, BPAK_OK);

    size_t pos = 0;
    unsigned int chunk_iteration = 0;
    while (pos < data_size) {
        size_t chunk = data_size - pos;
        if (chunk > BPAK_MERKLE_BLOCK_SZ)
            chunk = BPAK_MERKLE_BLOCK_SZ;
        if (unaligned)
            chunk = chunk_iteration++ % chunk + 1;

        rc = bpak_merkle_write_chunk(&ctx, &input_data[pos], chunk);
        assert_int_equal(rc, BPAK_OK);
        pos += chunk;
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_finish(&ctx, hash);
    assert_int_equal(rc, BPAK_OK);

    char root_hash_str[65];

    bpak_bin2hex(hash, sizeof(hash), root_hash_str, sizeof(root_hash_str));
    assert_string_equal(root_hash_str, expected_root_hash);

    free(merkle_buf);
    free(input_data);
}

/* Special case where there is only one hash block which is also the root */
static void test_merkle_4KiB(void **state)
{
    (void)state;
    check_merkle(
        4096,
        false,
        "d1af845007a3b73fb4836145f5d57e6912132e20adfc3acc3eca0a3be6d52d7d");
}

static void test_merkle_1MiB(void **state)
{
    (void)state;
    check_merkle(
        1024 * 1024,
        false,
        "8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436");
}

/* Pad/Boundary: 127 hashes on level 0 which requires 32b zero padding */
static void test_merkle_508KiB(void **state)
{
    (void)state;
    check_merkle(
        1024 * 508,
        false,
        "f60bd21616fe6875932dc462078856ca9bee23249d2d8e75bc1bb461b283bee6");
}

/* Pad/Boundary: 128 hashes on level 0, exactly one 4k hash block */
static void test_merkle_512KiB(void **state)
{
    (void)state;
    check_merkle(
        1024 * 512,
        false,
        "5499cb2ffae04fb8be71a75af64b38acc787c48cd026e523ab357ffc8bd44b19");
}

/* Pad/Boundary: 129 hashes on level 0, 4096 + 32 bytes of hashes */
static void test_merkle_516KiB(void **state)
{
    (void)state;
    check_merkle(
        1024 * 516,
        false,
        "6c574d8b52fa339dd08a468665033e370c4b228f9c91f25c796a96196b348fd6");
}

/* Pad/Boundary: 64 MiB results in exactly 4096 bytes of hashes in level 1 */
static void test_merkle_64MiB(void **state)
{
    (void)state;
    check_merkle(
        1024 * 1024 * 64,
        false,
        "501ee45cff77e8aaaf3db1fe6948d0ab061ba7d1f5063bc07d2b420e83d689c3");
}

/* Unaligned input must produce the same root hash as the 1MiB test */
static void test_merkle_unaligned_input(void **state)
{
    (void)state;
    check_merkle(
        1024 * 1024,
        true,
        "8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_merkle_tree_sizes),
        cmocka_unit_test(test_merkle_4KiB),
        cmocka_unit_test(test_merkle_1MiB),
        cmocka_unit_test(test_merkle_508KiB),
        cmocka_unit_test(test_merkle_512KiB),
        cmocka_unit_test(test_merkle_516KiB),
        cmocka_unit_test(test_merkle_64MiB),
        cmocka_unit_test(test_merkle_unaligned_input),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
