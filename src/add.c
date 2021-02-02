/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpak/pkg.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "bpak_tool.h"
#include "uuid/uuid.h"

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

static int add_file(struct bpak_header *h,
                     struct bpak_io *io,
                     const char *filename,
                     const char *part_name,
                     uint8_t flags)
{
    int rc;
    struct bpak_part_header *p = NULL;
    struct stat statbuf;
    uint64_t new_offset = sizeof(struct bpak_header);

    if (stat(filename, &statbuf) != 0)
    {
        printf("Error: can't open file '%s'\n", filename);
        return -BPAK_FAILED;
    }

    FILE *in_fp = NULL;

    if (bpak_get_verbosity())
        printf("Adding %s <%s>\n", part_name, filename);

    bpak_foreach_part(h, p)
    {
        new_offset += (p->size + p->pad_bytes);
    }

    rc = bpak_add_part(h, bpak_id(part_name), &p);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not add part\n");
        return rc;
    }

    p->id = bpak_id(part_name);
    p->offset = new_offset;
    p->flags = flags;
    p->size = statbuf.st_size;

    if (statbuf.st_size % BPAK_PART_ALIGN)
        p->pad_bytes = BPAK_PART_ALIGN - (statbuf.st_size % BPAK_PART_ALIGN);
    else
        p->pad_bytes = 0;

    /* Re-write header */
    rc = bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Error: Seek failed\n");
        return rc;
    }

    size_t written_bytes = bpak_io_write(io, h, sizeof(*h));

    if (written_bytes != sizeof(*h))
    {
        printf("Could not write header to file\n");
        return rc;
    }

    rc = bpak_io_seek(io, new_offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Could not seek to new pos\n");
        return rc;
    }

    uint64_t bytes_to_write = p->size;

    in_fp = fopen(filename, "r");

    if (!in_fp)
    {
        printf("Could not open input file: %s\n", filename);
        return -BPAK_FAILED;
    }

    char chunk_buffer[512];


    while (bytes_to_write)
    {
        size_t read_bytes = fread(chunk_buffer, 1, sizeof(chunk_buffer), in_fp);
        if (bpak_io_write(io, chunk_buffer, read_bytes) != read_bytes)
        {
            printf ("write error\n");
            rc = -BPAK_FAILED;
            break;
        }
        bytes_to_write -= read_bytes;
    }

    if (p->pad_bytes)
    {
        if (bpak_get_verbosity() > 1)
            printf("Adding %i z-pad\n", p->pad_bytes);
        memset(chunk_buffer, 0, sizeof(chunk_buffer));
        bpak_io_write(io, chunk_buffer, p->pad_bytes);
    }

    fclose(in_fp);
    return rc;
}

static int add_key(struct bpak_header *h,
                     struct bpak_io *io,
                     const char *filename,
                     const char *part_name,
                     uint8_t flags)
{
    int rc;
    char tmp[4096];
    struct bpak_part_header *p = NULL;
    struct stat statbuf;
    uint64_t new_offset = sizeof(struct bpak_header);
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    mbedtls_pk_parse_public_keyfile(&ctx, filename);

    int len = mbedtls_pk_write_pubkey_der(&ctx, tmp, sizeof(tmp));

    if (len < 0)
    {
        printf("Error: Could not load public key '%s'\n", filename);
        rc = -BPAK_FAILED;
        return rc;
    }

    if (bpak_get_verbosity())
    {
        printf("Loaded public key %i bytes\n", len);
    }

    mbedtls_pk_free(&ctx);

    /* Write header */
    bpak_foreach_part(h, p)
    {
        new_offset += (p->size + p->pad_bytes);
    }

    rc = bpak_add_part(h, bpak_id(part_name), &p);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not add part\n");
        return rc;
    }

    p->id = bpak_id(part_name);
    p->offset = new_offset;
    p->flags = 0;
    p->size = len;

    if (len % BPAK_PART_ALIGN)
        p->pad_bytes = BPAK_PART_ALIGN - (len % BPAK_PART_ALIGN);
    else
        p->pad_bytes = 0;

    /* Re-write header */
    rc = bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Error: Seek failed\n");
        return rc;
    }

    size_t written_bytes = bpak_io_write(io, h, sizeof(*h));

    if (written_bytes != sizeof(*h))
    {
        rc = -BPAK_FAILED;
        printf("Could not write header to file\n");
        return rc;
    }

    rc = bpak_io_seek(io, new_offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Could not seek to new pos\n");
        return rc;
    }

    char chunk_buffer[512];
    uint64_t bytes_to_write = p->size;
    uint64_t bytes_offset = 0;
    uint64_t chunk_sz = sizeof(chunk_buffer);


    while (bytes_to_write)
    {
        chunk_sz = (bytes_to_write > sizeof(chunk_buffer)) ? \
                            sizeof(chunk_buffer):bytes_to_write;

        memcpy(chunk_buffer, &tmp[sizeof(tmp) - len + bytes_offset], chunk_sz);

        if (bpak_io_write(io, chunk_buffer, chunk_sz) != chunk_sz)
        {
            printf ("write error\n");
            rc = -BPAK_FAILED;
            break;
        }
        bytes_to_write -= chunk_sz;
        bytes_offset += chunk_sz;
    }

    memset(chunk_buffer, 0, sizeof(chunk_buffer));
    bpak_io_write(io, chunk_buffer, p->pad_bytes);

    return rc;
}

static int add_merkle(struct bpak_header *h,
                     struct bpak_io *io,
                     const char *filename,
                     const char *part_name,
                     uint8_t flags)
{
    int rc;
    struct bpak_merkle_context ctx;
    struct stat statbuf;
    uint8_t block_buf[4096];
    size_t chunk_sz;
    uint64_t new_offset = sizeof(*h);

    if (stat(filename, &statbuf) != 0)
    {
        printf("Error: Can't open file '%s'\n", filename);
        return -1;
    }

    size_t merkle_sz = bpak_merkle_compute_size(statbuf.st_size, -1, true);
    char *merkle_buf = malloc(merkle_sz);

    memset(merkle_buf, 0, merkle_sz);

    if (bpak_get_verbosity())
        printf("Allocated %li bytes for merkle tree\n", merkle_sz);

    bpak_merkle_hash_t salt;
    memset(salt, 0, 32);

    uint32_t *salt_ptr = (uint32_t *) salt;

    for (int i = 0; i < sizeof(salt)/sizeof(uint32_t); i++)
    {
        (*salt_ptr) = random() & 0xFFFFFFFF;
        salt_ptr++;
    }

    rc = bpak_merkle_init(&ctx, statbuf.st_size, salt,
                            merkle_wr, merkle_rd, merkle_buf);

    if (bpak_get_verbosity())
    {
        for (int i = 0; i < ctx.no_of_levels; i++)
            printf("Level %i size %li bytes\n", i,
                    bpak_merkle_compute_size(statbuf.st_size, i, false));
    }

    if (bpak_get_verbosity())
        bpak_merkle_set_status_cb(&ctx, merkle_status);

    FILE *fp = fopen(filename, "rb");

    rc = BPAK_OK;
    while(true)
    {
        chunk_sz = fread(block_buf, 1, sizeof(block_buf), fp);

        if (chunk_sz == 0)
            break;

        rc = bpak_merkle_process(&ctx, block_buf, chunk_sz);

        if (rc != BPAK_OK)
            break;

    }

    fclose(fp);

    if (rc != BPAK_OK)
        goto err_free_buf;

    while (!bpak_merkle_done(&ctx))
    {
        rc = bpak_merkle_process(&ctx, NULL, 0);

        if (rc != BPAK_OK)
            break;
    }

    if (rc != BPAK_OK)
        goto err_free_buf;

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_out(&ctx, hash);

    if (bpak_get_verbosity())
    {
        printf ("Root hash: ");
        for (int i = 0; i < 32; i++)
            printf("%2.2x", hash[i] & 0xff);
        printf("\n");
    }

    /* Write tree to bpak file */

    bpak_foreach_part(h, p)
    {
        new_offset += (p->size + p->pad_bytes);
    }

    /* Add salt */
    uint8_t *m = NULL;
    char tmp[512];

    rc = bpak_add_meta(h, bpak_id("merkle-salt"), bpak_id(part_name), (void **) &m,
                            sizeof(bpak_merkle_hash_t));

    if (rc != BPAK_OK)
        return rc;

    memcpy(m, salt, sizeof(bpak_merkle_hash_t));

    m = NULL;
    rc = bpak_add_meta(h, bpak_id("merkle-root-hash"), bpak_id(part_name),
                        (void **) &m, sizeof(bpak_merkle_hash_t));

    if (rc != BPAK_OK)
        return rc;

    memcpy(m, hash, sizeof(bpak_merkle_hash_t));

    struct bpak_part_header *p = NULL;

    snprintf(tmp, sizeof(tmp), "%s-hash-tree", part_name);
    rc = bpak_add_part(h, bpak_id(tmp), &p);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not add part\n");
        return rc;
    }

    p->offset = new_offset;
    p->flags = flags;
    p->size = merkle_sz;
    p->pad_bytes = 0; /* Merkle tree is multiples of 4kByte, no padding needed */

    /* Re-write header */
    rc = bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Error: Seek failed\n");
        return rc;
    }

    size_t written_bytes = bpak_io_write(io, h, sizeof(*h));

    if (written_bytes != sizeof(*h))
    {
        printf("Could not write header to file\n");
        return rc;
    }

    rc = bpak_io_seek(io, new_offset, BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Could not seek to new pos\n");
        return rc;
    }

    rc = bpak_io_write(io, merkle_buf, merkle_sz);


err_free_buf:
    free(merkle_buf);

    return rc;
}


int action_add(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    uint32_t flags = 0;
    const char *filename = NULL;
    const char *part_name = NULL;
    const char *meta_name = NULL;
    const char *from_file = NULL;
    const char *from_string = NULL;
    const char *part_ref = NULL;
    const char *encoder = NULL;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"part",        required_argument, 0,  'p' },
        {"meta",        required_argument, 0,  'm' },
        {"from-file",   required_argument, 0,  'f' },
        {"from-string", required_argument, 0,  's' },
        {"encoder",     required_argument, 0,  'e' },
        {"set-flag",    required_argument, 0,  'F' },
        {"part-ref",    required_argument, 0,  'r' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvp:m:f:s:e:F:r:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_add_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'p':
                part_name = (const char *) optarg;
            break;
            case 'm':
                meta_name = (const char *) optarg;
            break;
            case 'r':
                part_ref = (const char *) optarg;
            break;
            case 'f':
                from_file = (const char *) optarg;
            break;
            case 's':
                from_string = (const char *) optarg;
            break;
            case 'e':
                encoder = (const char *) optarg;
            break;
            case 'F':
                if (strcmp(optarg, "dont-hash") == 0)
                    flags |= BPAK_FLAG_EXCLUDE_FROM_HASH;
                else
                {
                    printf("Unknown flag '%s'\n", optarg);
                    return -1;
                }
            break;
            case '?':
                printf("Unknown option: %c\n", optopt);
                return -1;
            break;
            case ':':
                printf("Missing arg for %c\n", optopt);
                return -1;
            break;
            default:
               return -1;
        }
    }

    if (optind < argc)
    {
        filename = (const char *) argv[optind++];
    }
    else
    {
        printf("Missing filename argument\n");
        return -1;
    }

    if (!part_name && !meta_name)
    {
        printf("Error: Requried argument --part or --meta is missing\n");
        return -1;
    }

    if (!from_string && !from_file)
    {
        printf("Error: either --from_string must be used or --from_file\n");
        return -1;
    }

    struct bpak_io *io = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    rc = bpak_io_init_file(&io, filename, "r+");

    if (rc != BPAK_OK)
    {
        printf("Could not open file '%s'\n", filename);
        goto err_free_header_out;
    }

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
    size_t read_bytes = bpak_io_read(io, h, sizeof(*h));

    if (read_bytes != sizeof(*h))
    {
        rc = -BPAK_FAILED;
        printf("Error: Could not read header %li\n", read_bytes);
        goto err_close_io_out;
    }

    rc = bpak_valid_header(h);

    if (rc != BPAK_OK)
    {
        printf("Error: Invalid header. Not a BPAK file?\n");
        goto err_close_io_out;
    }

    if (meta_name)
    {
        char *meta_data = NULL;
        uint32_t part_ref_id = 0;

        if (part_ref)
            part_ref_id = bpak_id(part_ref);

        /* Some known meta id's have predefined encoders */
        if (strcmp(meta_name, "bpak-dependency") == 0)
            encoder = "dependency";

        if (!from_string)
        {
            printf("Error: No input supplied with --from-string\n");
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }

        if (encoder)
        {
            if (strcmp(encoder, "uuid") == 0)
            {
                uuid_t uu;
                char uuid_text[37];
                rc = uuid_parse(from_string, uu);

                if (rc != 0)
                {
                    rc = -BPAK_FAILED;
                    printf("Error: Could not convert UUID string\n");
                    goto err_close_io_out;
                }

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                                (void **) &meta_data, 16);

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_io_out;
                }

                memcpy(meta_data, uu, 16);

                if(bpak_get_verbosity())
                {
                    uuid_unparse(meta_data, uuid_text);
                    printf("Adding %s <%s>\n", meta_name, uuid_text);
                }
            }
            else if (strcmp(encoder, "integer") == 0)
            {
                long value = strtol(from_string, NULL, 0);

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                        (void **) &meta_data, sizeof(value));

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_io_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if(bpak_get_verbosity())
                {
                    printf("Adding %s <0x%lx>\n", meta_name, value);
                }
            }
            else if (strcmp(encoder, "id") == 0)
            {
                uint32_t value = bpak_id(from_string);

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                        (void **) &meta_data, sizeof(value));

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_io_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if(bpak_get_verbosity())
                {
                    printf("Adding %s <%x>\n", meta_name, value);
                }
            }
            else if (strcmp(encoder, "dependency") == 0)
            {
                /* Dependency format: <uuid>-<semver>*/
                struct bpak_dependency *d;

                char uuid_text[37];
                char *constraint_ptr = (char *) &from_string[37];

                memset(uuid_text, 0, sizeof(uuid_text));
                memcpy(uuid_text, from_string, 36);

                if (from_string[36] != ':')
                {
                    rc = -BPAK_FAILED;
                    printf("Error: malformed constraint\n");
                    goto err_close_io_out;
                }

                size_t meta_size = sizeof(*d) + strlen(constraint_ptr);

                rc = bpak_add_meta(h, bpak_id(meta_name), 0,
                          (void **) &d, meta_size);

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_io_out;
                }

                rc = uuid_parse(uuid_text, d->uuid);

                if (rc != 0)
                {
                    rc = -BPAK_FAILED;
                    printf("Error: Could not convert UUID string\n");
                    goto err_close_io_out;
                }

                strncpy(d->constraint, constraint_ptr,
                                        meta_size - sizeof(*d));

                if(bpak_get_verbosity())
                {
                    printf("Adding dependency %s\n", from_string);
                }
            }
            else
            {
                printf("Error: Unknown encoder\n");
                rc = -BPAK_FAILED;
                goto err_close_io_out;
            }
        }
        else
        {
            if (bpak_get_verbosity())
                printf("Adding '%s' with id '%s'\n", from_string, meta_name);

            rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                (void **) &meta_data, strlen(from_string) + 1);

            if (rc != BPAK_OK)
            {
                printf("Error: Could not add meta data\n");
                goto err_close_io_out;
            }

            memcpy(meta_data, from_string, strlen(from_string));
        }

        if (bpak_get_verbosity() > 2)
            printf("Meta data array pointer = %p\n", meta_data);

        rc = bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

        if (rc != BPAK_OK)
        {
            printf("Error: Seek failed\n");
            goto err_close_io_out;
        }

        size_t written_bytes = bpak_io_write(io, h, sizeof(*h));

        if (written_bytes != sizeof(*h))
        {
            rc = -BPAK_FAILED;
            printf("Could not write to file\n");
            goto err_close_io_out;
        }
    }
    else if (part_name && !encoder)
    {
        rc = add_file(h, io, from_file, part_name, flags);
    }
    else if (part_name && strcmp(encoder, "key") == 0)
    {
        rc = add_key(h, io, from_file, part_name, flags);
    }
    else if (strcmp(encoder, "merkle") == 0)
    {
        if (bpak_get_verbosity())
            printf("Writing filesystem...\n");
        rc = add_file(h, io, from_file, part_name, flags);

        if (rc != BPAK_OK)
            goto err_close_io_out;

        if (bpak_get_verbosity())
            printf("Building merkle tree...\n");

        rc = add_merkle(h, io, from_file, part_name, flags);

    }
    else
    {
        printf("Error: Unknown command\n");
        rc = -BPAK_FAILED;
    }

err_close_io_out:
    bpak_io_close(io);
err_free_header_out:
    free(h);
    return rc;
}
