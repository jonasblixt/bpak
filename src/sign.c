/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <bpak/bpak.h>
#include <bpak/io.h>
#include <bpak/crypto.h>

#include "bpak_tool.h"

static int load_private_key(const char *filename, struct bpak_key **k)
{
    int rc = BPAK_OK;
    char tmp[4096];
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    mbedtls_pk_parse_keyfile(&ctx, filename, NULL);

    int len = mbedtls_pk_write_key_der(&ctx, tmp, sizeof(tmp));

    if (len < 0)
    {
        printf("Error: Could not load private key (%i)\n", len);
        rc = -BPAK_FAILED;
        goto err_free_ctx;
    }

    if (bpak_get_verbosity() > 1)
    {
        printf("Loaded private key %i bytes\n", len);
    }

    *k = malloc(sizeof(struct bpak_key) + len);

    struct bpak_key *key = *k;

    key->size = len;

    if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0)
    {
        switch (mbedtls_pk_get_bitlen(&ctx))
        {
            case 256:
                key->kind = BPAK_KEY_PRI_PRIME256v1;
            break;
            case 384:
                key->kind = BPAK_KEY_PRI_SECP384r1;
            break;
            case 521:
                key->kind = BPAK_KEY_PRI_SECP521r1;
            break;
            default:
                printf("Unknown bit-length (%li)\n",
                        mbedtls_pk_get_bitlen(&ctx));
                rc = -BPAK_FAILED;
                goto err_free_ctx;
        };
    }
    else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0)
    {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096)
        {
            key->kind = BPAK_KEY_PRI_RSA4096;
        }
        else
        {
            printf("Unknown bit-length (%li)\n",
                    mbedtls_pk_get_bitlen(&ctx));
            rc = -BPAK_FAILED;
            goto err_free_ctx;
        }
    }
    else
    {
        printf("Error: Unknown key type (%s)\n", mbedtls_pk_get_name(&ctx));
        rc = -BPAK_FAILED;
        goto err_free_ctx;
    }
    memcpy(key->data, &tmp[sizeof(tmp) - len], len);

err_free_ctx:
    mbedtls_pk_free(&ctx);
    return rc;
}

static int load_public_key(const char *filename, struct bpak_key **k)
{
    int rc = BPAK_OK;
    char tmp[4096];
    mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
    mbedtls_pk_parse_public_keyfile(&ctx, filename);

    int len = mbedtls_pk_write_pubkey_der(&ctx, tmp, sizeof(tmp));

    if (len < 0)
    {
        printf("Error: Could not load public key (%i)\n", len);
        rc = -BPAK_FAILED;
        goto err_free_ctx;
    }

    if (bpak_get_verbosity())
    {
        printf("Loaded public key %i bytes\n", len);
    }

    *k = malloc(sizeof(struct bpak_key) + len);

    struct bpak_key *key = *k;

    key->size = len;

    if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0)
    {
        switch (mbedtls_pk_get_bitlen(&ctx))
        {
            case 256:
                key->kind = BPAK_KEY_PUB_PRIME256v1;
            break;
            case 384:
                key->kind = BPAK_KEY_PUB_SECP384r1;
            break;
            case 521:
                key->kind = BPAK_KEY_PUB_SECP521r1;
            break;
            default:
                printf("Unknown bit-length (%li)\n",
                        mbedtls_pk_get_bitlen(&ctx));
                rc = -BPAK_FAILED;
                goto err_free_ctx;
        };
    }
    else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0)
    {
        if (mbedtls_pk_get_bitlen(&ctx) == 4096)
        {
            key->kind = BPAK_KEY_PUB_RSA4096;
        }
        else
        {
            printf("Unknown bit-length (%li)\n",
                    mbedtls_pk_get_bitlen(&ctx));
            rc = -BPAK_FAILED;
            goto err_free_ctx;
        }
    }
    else
    {
        printf("Error: Unknown key type (%s)\n", mbedtls_pk_get_name(&ctx));
        rc = -BPAK_FAILED;
        goto err_free_ctx;
    }

    memcpy(key->data, &tmp[sizeof(tmp) - len], len);
err_free_ctx:
    mbedtls_pk_free(&ctx);
    return rc;
}

int action_sign(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    const char *filename = NULL;
    const char *signature_file = NULL;
    const char *key_source = NULL;
    const char *key_store = NULL;
    const char *key_id = NULL;
    const char *hash_alg = NULL;
    char sig[1024];
    size_t size = sizeof(sig);
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"hash",        required_argument, 0,  'H' },
        {"key",         required_argument, 0,  'k' },
        {"key-store",   required_argument, 0,  's' },
        {"key-id",      required_argument, 0,  'i' },
        {"signature",   required_argument, 0,  'f' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvk:s:i:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_sign_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'k':
                key_source = (const char *) optarg;
            break;
            case 's':
                key_store = (const char *) optarg;
            break;
            case 'i':
                key_id = (const char *) optarg;
            break;
            case 'f':
                signature_file = (const char *) optarg;
            break;
            case 'H':
                hash_alg = (const char *) optarg;
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

    struct bpak_io *io = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    rc = bpak_io_init_file(&io, filename, "r+");

    if (rc != BPAK_OK)
        goto err_free_header_out;

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

    if (!key_id || !key_store)
    {
        printf("Error: Missing argument key-id or key-store\n");
        rc = -BPAK_FAILED;
        goto err_close_io_out;
    }

    uint32_t *key_id_ptr = NULL;
    uint32_t *key_store_ptr = NULL;

    rc = bpak_get_meta(h, id("bpak-key-id"), (void **) &key_id_ptr);

    if (rc != BPAK_OK)
        rc = bpak_add_meta(h, id("bpak-key-id"), 0, (void **) &key_id_ptr,
                        sizeof(uint32_t));

    if (rc != BPAK_OK)
    {
        printf("Error: Could not add bpak-key-id\n");
        goto err_close_io_out;
    }

    rc = bpak_get_meta(h, id("bpak-key-store"), (void **) &key_store_ptr);

    if (rc != BPAK_OK)
        rc = bpak_add_meta(h, id("bpak-key-store"), 0, (void **) &key_store_ptr,
                                sizeof(uint32_t));

    if (rc != BPAK_OK)
    {
        printf("Error: Could not add bpak-key-store\n");
        goto err_close_io_out;
    }

    *key_id_ptr = id(key_id);
    *key_store_ptr = id(key_store);

    FILE *sig_fp = NULL;

    if (signature_file)
    {
        sig_fp = fopen(signature_file, "r");

        size = fread(sig, 1, sizeof(sig), sig_fp);

        fclose(sig_fp);
        if (bpak_get_verbosity())
            printf("Loaded signature %li bytes\n", size);

        if (bpak_get_verbosity() > 1)
        {
            printf("Signature: ");
            for (int i = 0; i < size; i++)
                printf("%2.2x", sig[i] & 0xff);
            printf("\n");
        }

        bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

        uint8_t *signature_ptr = NULL;

        bpak_foreach_meta(h, m)
        {
            if (m->id == id("bpak-signature"))
            {
                uint8_t *ptr = &h->metadata[m->offset];
                memset(ptr, 0, m->size);
                memset(m, 0, sizeof(*m));
                m->id = id("bpak-signature");
                m->size = size;
                break;
            }
        }

        bpak_get_meta(h, id("bpak-signature"), (void **) &signature_ptr);

        if (!signature_ptr)
        {
            bpak_add_meta(h, id("bpak-signature"), 0,
                                (void **) &signature_ptr, size);
        }

        memcpy(signature_ptr, sig, size);

        bpak_io_write(io, h, sizeof(*h));

        rc = BPAK_OK;
        goto err_close_io_out;
    }

    struct bpak_hash_context hash;

    rc = bpak_hash_init(&hash, h->hash_kind);

    if (rc != BPAK_OK)
        goto err_free_header_out;

    /* Remove existing signature */
    bpak_foreach_meta(h, m)
    {
        if (m->id == id("bpak-signature"))
        {
            uint8_t *ptr = &h->metadata[m->offset];
            memset(ptr, 0, m->size);
            memset(m, 0, sizeof(*m));
        }
    }

    bpak_hash_update(&hash, h, sizeof(*h));

    char hash_buffer[512];
    char hash_output[65];

    rc = bpak_io_seek(io, sizeof(*h), BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Seek error\n");
    }

    bpak_foreach_part(h, p)
    {
        size_t bytes_to_read = p->size + p->pad_bytes;
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
            continue;

        if (bpak_get_verbosity() > 1)
        {
            printf("Hashing part %x, %li bytes\n", p->id, p->size);
        }

        rc = bpak_io_seek(io, bpak_part_offset(h, p), BPAK_IO_SEEK_SET);

        if (rc != BPAK_OK)
        {
            printf("Seek error\n");
            printf("    offset:  %li\n", bpak_part_offset(h, p));
            printf("    pos:     %li\n", bpak_io_tell(io));
            break;
        }

        do
        {
            chunk = (bytes_to_read > sizeof(hash_buffer))?
                        sizeof(hash_buffer):bytes_to_read;

            bpak_io_read(io, hash_buffer, chunk);
            bpak_hash_update(&hash, hash_buffer, chunk);
            bytes_to_read -= chunk;
        } while (bytes_to_read);
    }

    if (rc != BPAK_OK)
        goto err_close_io_out;

    bpak_hash_out(&hash, hash_output, sizeof(hash_output));

    if (bpak_get_verbosity())
    {
        printf("Computed hash: ");
        for (int i = 0; i < hash.size; i++)
            printf("%2.2x", (char ) hash_output[i] & 0xff);
        printf("\n");
    }

    struct bpak_key *sign_key = NULL;

    rc = load_private_key(key_source, &sign_key);

    if (rc != BPAK_OK)
       goto err_free_sign_key;

    if (bpak_get_verbosity() > 1)
    {
        for (int i = 0; i < sign_key->size; i++)
            printf("%2.2x ", sign_key->data[i] & 0xff);
        printf("\n");
    }

    struct bpak_sign_context ctx_sign;

    rc = bpak_sign_init(&ctx_sign, sign_key);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not initialize signing context\n");
        goto err_free_sign_key;
    }


    rc = bpak_sign(&ctx_sign, &hash, sig, &size);

    if (rc != BPAK_OK)
    {
        printf("Error: Signing failed\n");
        goto err_free_sign_ctx;
    }

    if (bpak_get_verbosity() > 1)
    {
        printf("Signature: ");
        for (int i = 0; i < size; i++)
            printf("%2.2x", sig[i] & 0xff);
        printf("\n");
    }

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    uint8_t *signature_ptr = NULL;

    bpak_get_meta(h, id("bpak-signature"), (void **) &signature_ptr);

    if (!signature_ptr)
    {
        bpak_add_meta(h, id("bpak-signature"), 0, (void **) &signature_ptr, size);
    }

    memcpy(signature_ptr, sig, size);

    bpak_io_write(io, h, sizeof(*h));

err_free_sign_ctx:
    bpak_sign_free(&ctx_sign);
err_free_sign_key:
    free(sign_key);
err_free_hash_ctx:
    bpak_hash_free(&hash);
err_free_header_out:
    free(h);
err_close_io_out:
    bpak_io_close(io);
    return rc;
}

int action_verify(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    const char *filename = NULL;
    const char *key_source = NULL;
    const char *hash_alg = NULL;

    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"hash",        required_argument, 0,  'H' },
        {"key",         required_argument, 0,  'k' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvk:H:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_sign_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'k':
                key_source = (const char *) optarg;
            break;
            case 'H':
                hash_alg = (const char *) optarg;
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

    struct bpak_io *io = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    rc = bpak_io_init_file(&io, filename, "r+");

    if (rc != BPAK_OK)
        goto err_free_header_out;

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

    struct bpak_hash_context hash;

    rc = bpak_hash_init(&hash, h->hash_kind);

    if (rc != BPAK_OK)
        goto err_free_header_out;

    uint8_t signature[1024];
    uint8_t signature_sz = 0;

    /* Copy and zero out the signature metadata before hasing header */
    bpak_foreach_meta(h, m)
    {
        if (m->id == id("bpak-signature"))
        {
            uint8_t *ptr = &h->metadata[m->offset];
            signature_sz = m->size;
            memcpy(signature, ptr, m->size);
            memset(ptr, 0, m->size);
            memset(m, 0, sizeof(*m));
        }
    }

    bpak_hash_update(&hash, h, sizeof(*h));

    char hash_buffer[512];
    char hash_output[64];

    bpak_foreach_part(h, p)
    {
        size_t bytes_to_read = p->size + p->pad_bytes;
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
        {
            if (bpak_get_verbosity())
                printf("Skipping part %x\n", p->id);
            bpak_io_seek(io, p->size, BPAK_IO_SEEK_FWD);
            continue;
        }

        if (bpak_get_verbosity())
        {
            printf("Hashing part %x, %li bytes\n", p->id, p->size);
        }

        do
        {
            chunk = (bytes_to_read > sizeof(hash_buffer))?
                        sizeof(hash_buffer):bytes_to_read;

            bpak_io_read(io, hash_buffer, chunk);
            bpak_hash_update(&hash, hash_buffer, chunk);
            bytes_to_read -= chunk;
        } while (bytes_to_read);
    }

    bpak_hash_out(&hash, hash_output, sizeof(hash_output));

    if (bpak_get_verbosity() > 1)
    {
        printf("Computed hash: ");
        for (int i = 0; i < 32; i++)
            printf("%2.2x", (char ) hash_output[i] & 0xff);
        printf("\n");
    }

    struct bpak_key *sign_key = NULL;

    rc = load_public_key(key_source, &sign_key);

    if (rc != BPAK_OK)
        goto err_free_sign_key;

    if (bpak_get_verbosity() > 1)
    {
        for (int i = 0; i < sign_key->size; i++)
            printf("%2.2x ", sign_key->data[i] & 0xff);
        printf("\n");
    }

    struct bpak_sign_context ctx_sign;

    rc = bpak_sign_init(&ctx_sign, sign_key);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not initialize signing context\n");
        goto err_free_sign_key;
    }

    rc = bpak_verify(&ctx_sign, &hash, signature, signature_sz);

    if (rc != BPAK_OK)
    {
        printf("Error: Verification failed\n");
        goto err_free_sign_ctx;
    }

    printf("Verification OK\n");

err_free_sign_ctx:
    bpak_sign_free(&ctx_sign);
err_free_sign_key:
    free(sign_key);
err_free_hash_ctx:
    bpak_hash_free(&hash);
err_free_header_out:
    free(h);
err_close_io_out:
    bpak_io_close(io);
    return rc;
}
