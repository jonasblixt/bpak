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
 * Salt:                   65498d387f3c28382752721c5a4e5a551c1b3370b7967458de7c7c4f2cd2e97a
 * Root hash:              539da407d732ba00bb3c83d7c36803696576e0316a63c728b061735f413f25f7
 *
 *
veritysetup format arne asdf -s 0000000000000000000000000000000000000000000000000000000000000000
 VERITY header information for asdf
UUID:                   03383d6b-862f-42b3-812b-43b44dff859a
Hash type:              1
Data blocks:            1024
Data block size:        4096
Hash block size:        4096
Hash algorithm:         sha256
Salt:                   0000000000000000000000000000000000000000000000000000000000000000
Root hash:              45ba0f2e75da95d3c895fa348f4dbe3020e7fbc784d57d3169ecbe3751bd9031

UUID:                   004b396f-b46c-4cec-aead-910bccf640dd
Hash type:              1
Data blocks:            1024
Data block size:        4096
Hash block size:        4096
Hash algorithm:         sha256
Salt:                   -
Root hash:              2f71d6f2e44801bb8bd97e5b66a0e82b1588b24d684728a46093cdb29b3178d6

 *
 *
 */

static int merkle_wr(struct bpak_merkle_context *ctx,
                        uint64_t offset,
                        uint8_t *buf,
                        size_t size,
                        void *priv)
{
    uint8_t *data = (uint8_t *) priv;
    memcpy(&data[offset], buf, size);
    return BPAK_OK;
}

static int merkle_rd(struct bpak_merkle_context *ctx,
                        uint64_t offset,
                        uint8_t *buf,
                        size_t size,
                        void *priv)
{
    uint8_t *data = (uint8_t *) priv + offset;
    memcpy(buf, data, size);
    return BPAK_OK;
}

static void merkle_status(struct bpak_merkle_context *ctx)
{
    if ((ctx->current.byte_counter % (MERKLE_BLOCK_SZ)) == 0)
    {
        printf("\r %i: %li %%", ctx->current.level,
            100 * ctx->current.byte_counter / ctx->current.size);
        fflush(stdout);
    }
    else if(ctx->current.byte_counter == ctx->current.size)
    {
        printf("\r %i: 100 %%\n", ctx->current.level);
    }
}

TEST(merkle_odd)
{
    int rc;
    struct bpak_merkle_context ctx;
    char *input_data = malloc(1024*1023);
    size_t merkle_sz = bpak_merkle_compute_size(1024*1023, -1, true);
    char *merkle_buf = malloc(merkle_sz);

    memset(&ctx, 0, sizeof(ctx));

    for (int i = 0; i < (1024*1023); i += 16)
        memcpy(&input_data[i], "0123456789abcdef", 16);

    FILE *fp = fopen("merkle_input_odd", "w");
    fwrite(input_data, 1024, 1023, fp);
    fclose(fp);

    memset(merkle_buf, 0, merkle_sz);

    printf("Allocated %li bytes for merkle tree\n", merkle_sz);

    char salt[] =
    {
        0x65,
        0x49,
        0x8d,
        0x38,
        0x7f,
        0x3c,
        0x28,
        0x38,
        0x27,
        0x52,
        0x72,
        0x1c,
        0x5a,
        0x4e,
        0x5a,
        0x55,
        0x1c,
        0x1b,
        0x33,
        0x70,
        0xb7,
        0x96,
        0x74,
        0x58,
        0xde,
        0x7c,
        0x7c,
        0x4f,
        0x2c,
        0xd2,
        0xe9,
        0x7a,
    };

/* 8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436*/
    rc = bpak_merkle_init(&ctx, 1024*1023, salt,
                            merkle_wr, merkle_rd, merkle_buf);

    for (int i = 0; i < ctx.no_of_levels; i++)
        printf("Level %i size %li bytes\n", i,
                bpak_merkle_compute_size(1024*1023, i, false));

    bpak_merkle_set_status_cb(&ctx, merkle_status);

    uint32_t data_to_process = 1024*1023;
    uint32_t pos = 0;
    while(data_to_process)
    {
        uint32_t chunk = (data_to_process > MERKLE_BLOCK_SZ) ? \
                                    MERKLE_BLOCK_SZ:data_to_process;
        rc = bpak_merkle_process(&ctx, &input_data[pos], chunk);
        pos += chunk;
        data_to_process -= chunk;

        ASSERT_EQ(rc, BPAK_OK);
    }

    while (!bpak_merkle_done(&ctx))
    {
        rc = bpak_merkle_process(&ctx, NULL, 0);
        ASSERT_EQ(rc, BPAK_OK);
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_out(&ctx, hash);
    ASSERT_EQ(rc, BPAK_OK);


    fp = fopen("merkle_out_odd", "wb");
    fwrite(merkle_buf, 1, merkle_sz, fp);
    fclose(fp);

    char root_hash_str[65];
    char salt_str[65];

    bpak_bin2hex(salt, 32, salt_str, sizeof(salt_str));
    bpak_bin2hex(hash, 32, root_hash_str, sizeof(salt_str));
    printf("Salt:      %s\n", salt_str);
    printf("Root hash: %s\n", root_hash_str);

    ASSERT_EQ((char *)root_hash_str, \
        "74d62b0b4eb3358e9079a52800b3f066576c63c4ed8fccc3a7510da992212bd7");

    free(merkle_buf);
    free(input_data);
}

TEST(merkle_even)
{
    int rc;
    struct bpak_merkle_context ctx;
    char *input_data = malloc(1024*1024);
    size_t merkle_sz = bpak_merkle_compute_size(1024*1024, -1, true);
    char *merkle_buf = malloc(merkle_sz);

    memset(&ctx, 0, sizeof(ctx));

    for (int i = 0; i < (1024*1024); i += 16)
        memcpy(&input_data[i], "0123456789abcdef", 16);


    FILE *fp = fopen("merkle_input_even", "w");
    fwrite(input_data, 1024, 1024, fp);
    fclose(fp);

    memset(merkle_buf, 0, merkle_sz);

    printf("Allocated %li bytes for merkle tree\n", merkle_sz);

    char salt[] =
    {
        0x65,
        0x49,
        0x8d,
        0x38,
        0x7f,
        0x3c,
        0x28,
        0x38,
        0x27,
        0x52,
        0x72,
        0x1c,
        0x5a,
        0x4e,
        0x5a,
        0x55,
        0x1c,
        0x1b,
        0x33,
        0x70,
        0xb7,
        0x96,
        0x74,
        0x58,
        0xde,
        0x7c,
        0x7c,
        0x4f,
        0x2c,
        0xd2,
        0xe9,
        0x7a,
    };

/* 8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436*/
    rc = bpak_merkle_init(&ctx, 1024*1024, salt,
                            merkle_wr, merkle_rd, merkle_buf);

    for (int i = 0; i < ctx.no_of_levels; i++)
        printf("Level %i size %li bytes\n", i,
                bpak_merkle_compute_size(1024*1024, i, false));

    bpak_merkle_set_status_cb(&ctx, merkle_status);

    uint32_t data_to_process = 1024*1024;
    uint32_t pos = 0;
    while(data_to_process)
    {
        uint32_t chunk = (data_to_process > MERKLE_BLOCK_SZ) ? \
                                    MERKLE_BLOCK_SZ:data_to_process;
        rc = bpak_merkle_process(&ctx, &input_data[pos], chunk);
        pos += chunk;
        data_to_process -= chunk;

        ASSERT_EQ(rc, BPAK_OK);
    }

    while (!bpak_merkle_done(&ctx))
    {
        rc = bpak_merkle_process(&ctx, NULL, 0);
        ASSERT_EQ(rc, BPAK_OK);
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_out(&ctx, hash);
    ASSERT_EQ(rc, BPAK_OK);

    fp = fopen("merkle_out_even", "wb");
    fwrite(merkle_buf, 1, merkle_sz, fp);
    fclose(fp);

    char root_hash_str[65];
    char salt_str[65];

    bpak_bin2hex(salt, 32, salt_str, sizeof(salt_str));
    bpak_bin2hex(hash, 32, root_hash_str, sizeof(salt_str));
    printf("Salt:      %s\n", salt_str);
    printf("Root hash: %s\n", root_hash_str);

    ASSERT_EQ((char *)root_hash_str, \
        "8effc062924445d3389c6b360b29cf1c142d29497df783a63eabcea6f7779436");


    free(merkle_buf);
    free(input_data);
}
