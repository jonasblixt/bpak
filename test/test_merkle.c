#include <stdint.h>
#include <ctype.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/merkle.h>
#include "nala.h"
/*
 *
 * VERITY header information for asdf
 * UUID:                   6b65c14f-32ea-404b-99b1-e42d39722f7f
 * Hash type:              1
 * Data blocks:            1024
 * Data block size:        4096
 * Hash block size:        4096
 * Hash algorithm:         sha256
 * Salt: 65498d387f3c28382752721c5a4e5a551c1b3370b7967458de7c7c4f2cd2e97a
 * Root hash: 539da407d732ba00bb3c83d7c36803696576e0316a63c728b061735f413f25f7
 *
 *
veritysetup format arne asdf -s
0000000000000000000000000000000000000000000000000000000000000000 VERITY header
information for asdf UUID: 03383d6b-862f-42b3-812b-43b44dff859a Hash type: 1
Data blocks:            1024
Data block size:        4096
Hash block size:        4096
Hash algorithm:         sha256
Salt: 0000000000000000000000000000000000000000000000000000000000000000 Root
hash: 45ba0f2e75da95d3c895fa348f4dbe3020e7fbc784d57d3169ecbe3751bd9031

UUID:                   004b396f-b46c-4cec-aead-910bccf640dd
Hash type:              1
Data blocks:            1024
Data block size:        4096
Hash block size:        4096
Hash algorithm:         sha256
Salt:                   -
Root hash: 2f71d6f2e44801bb8bd97e5b66a0e82b1588b24d684728a46093cdb29b3178d6

 *
 *
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

TEST(merkle_tree_sizes)
{
    ssize_t merkle_sz = 0;

    merkle_sz = bpak_merkle_compute_size(1024 * 4 * 2);
    ASSERT_EQ(merkle_sz, 4096);

    merkle_sz = bpak_merkle_compute_size(1024 * 4);
    ASSERT_EQ(merkle_sz, 4096);

    merkle_sz = bpak_merkle_compute_size(16);
    ASSERT_EQ(merkle_sz, -BPAK_BAD_ALIGNMENT);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024);
    ASSERT_EQ(merkle_sz, 8458240);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 2l);
    ASSERT_EQ(merkle_sz, 16912384);

    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 1024l);
    ASSERT_EQ(merkle_sz, 8657571840);

    /* 1 TiB is the largest supported input data  with four levels */
    merkle_sz = bpak_merkle_compute_size(1024 * 1024 * 1024 * 1024l + 4096);
    ASSERT_EQ(merkle_sz, -BPAK_NO_SPACE_LEFT);
}

static void test_merkle(const char *test_name, size_t data_size,
                        const char *expected_root_hash)
{
    int rc;
    struct bpak_merkle_context ctx;
    uint8_t *input_data = malloc(data_size);
    size_t merkle_sz = bpak_merkle_compute_size(data_size);
    char *merkle_buf = malloc(merkle_sz);

    memset(&ctx, 0, sizeof(ctx));

    for (unsigned int i = 0; i < data_size; i += 16)
        memcpy(&input_data[i], "0123456789abcdef", 16);

    FILE *fp = fopen(test_name, "w");
    fwrite(input_data, 1, data_size, fp);
    fclose(fp);

    memset(merkle_buf, 0, merkle_sz);

    printf("Allocated %li bytes for merkle tree\n", merkle_sz);

    /* 8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436*/
    rc = bpak_merkle_init(&ctx,
                          data_size,
                          salt,
                          sizeof(salt),
                          merkle_wr,
                          merkle_rd,
                          0,
                          true,
                          merkle_buf);

    uint32_t data_to_process = data_size;
    uint32_t pos = 0;
    while (data_to_process) {
        uint32_t chunk = (data_to_process > BPAK_MERKLE_BLOCK_SZ)
                             ? BPAK_MERKLE_BLOCK_SZ
                             : data_to_process;
        rc = bpak_merkle_write_chunk(&ctx, &input_data[pos], chunk);
        pos += chunk;
        data_to_process -= chunk;

        ASSERT_EQ(rc, BPAK_OK);
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_finish(&ctx, hash);
    ASSERT_EQ(rc, BPAK_OK);

    char root_hash_str[65];
    char salt_str[65];

    bpak_bin2hex((uint8_t *)salt, 32, salt_str, sizeof(salt_str));
    bpak_bin2hex(hash, 32, root_hash_str, sizeof(salt_str));
    printf("Salt:      %s\n", salt_str);
    printf("Root hash: %s\n", root_hash_str);

    ASSERT_EQ((char *)root_hash_str, expected_root_hash);
    free(merkle_buf);
    free(input_data);
}

TEST(merkle_4KiB)
{
    /* This tests a special case where there is only one hash block which
     * is also the reult, the root hash */
    test_merkle(
        "merkle_test_4KiB.bin",
        4096,
        "d1af845007a3b73fb4836145f5d57e6912132e20adfc3acc3eca0a3be6d52d7d");
}

TEST(merkle_1MiB)
{
    test_merkle(
        "merkle_test_1MiB.bin",
        1024 * 1024,
        "8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436");
}

/* Pad/Boundary test
 *
 * This test produces 127 hashes on level 0 which requires 32b zero padding */
TEST(merkle_508KiB)
{
    test_merkle(
        "merkle_test_508KiB.bin",
        1024 * 508,
        "f60bd21616fe6875932dc462078856ca9bee23249d2d8e75bc1bb461b283bee6");
}

/* Pad/Boundary test
 *
 * This test produces 128 hashes on level 0 which results in exactly
 * one 4k hash block*/
TEST(merkle_512KiB)
{
    test_merkle(
        "merkle_test_512KiB.bin",
        1024 * 512,
        "5499cb2ffae04fb8be71a75af64b38acc787c48cd026e523ab357ffc8bd44b19");
}

/* Pad/Boundary test
 *
 * This test produces 129 hashes on level 0 which results in 4096 + 32 bytes
 * of hashes in level 0 */
TEST(merkle_516KiB)
{
    test_merkle(
        "merkle_test_516KiB.bin",
        1024 * 516,
        "6c574d8b52fa339dd08a468665033e370c4b228f9c91f25c796a96196b348fd6");
}

/* Pad/Boundary test
 *
 * 64 MiB results in exactly 4096 bytes of hashes in level 1 */
TEST(merkle_64MiB)
{
    test_merkle(
        "merkle_test_64MiB.bin",
        1024 * 1024 * 64,
        "501ee45cff77e8aaaf3db1fe6948d0ab061ba7d1f5063bc07d2b420e83d689c3");
}

/* This tests that the chunk write function handles unaligned input correctly
 */
TEST(merkle_unaligned_input)
{
    int rc;
    size_t data_size = 1024 * 1024;
    const char *test_name = "merkle_unaligned_input.bin";
    struct bpak_merkle_context ctx;
    uint8_t *input_data = malloc(data_size);
    size_t merkle_sz = bpak_merkle_compute_size(data_size);
    char *merkle_buf = malloc(merkle_sz);

    memset(&ctx, 0, sizeof(ctx));

    for (unsigned int i = 0; i < data_size; i += 16)
        memcpy(&input_data[i], "0123456789abcdef", 16);

    FILE *fp = fopen(test_name, "w");
    fwrite(input_data, 1, data_size, fp);
    fclose(fp);

    memset(merkle_buf, 0, merkle_sz);

    printf("Allocated %li bytes for merkle tree\n", merkle_sz);

    /* 8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436*/
    rc = bpak_merkle_init(&ctx,
                          data_size,
                          salt,
                          sizeof(salt),
                          merkle_wr,
                          merkle_rd,
                          0,
                          true,
                          merkle_buf);

    uint32_t data_to_process = data_size;
    uint32_t pos = 0;
    unsigned int chunk_iteration = 0;
    while (data_to_process) {
        uint32_t chunk = (data_to_process > BPAK_MERKLE_BLOCK_SZ)
                             ? BPAK_MERKLE_BLOCK_SZ
                             : data_to_process;

        chunk = chunk_iteration % chunk + 1;

        printf("Writing %i bytes\n", chunk);
        rc = bpak_merkle_write_chunk(&ctx, &input_data[pos], chunk);
        pos += chunk;
        data_to_process -= chunk;
        chunk_iteration += 1;

        ASSERT_EQ(rc, BPAK_OK);
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_finish(&ctx, hash);
    ASSERT_EQ(rc, BPAK_OK);

    char root_hash_str[65];
    char salt_str[65];

    bpak_bin2hex((uint8_t *)salt, 32, salt_str, sizeof(salt_str));
    bpak_bin2hex(hash, 32, root_hash_str, sizeof(salt_str));
    printf("Salt:      %s\n", salt_str);
    printf("Root hash: %s\n", root_hash_str);

    ASSERT_EQ(
        (char *)root_hash_str,
        "8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436");
    free(merkle_buf);
    free(input_data);
}
