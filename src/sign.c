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
#include <bpak/pkg.h>

#include "bpak_tool.h"

static int hash_kind(int bpak_hash_kind)
{
    int hash_kind = 0;

    switch (bpak_hash_kind)
    {
        case BPAK_HASH_SHA256:
            hash_kind = MBEDTLS_MD_SHA256;
        break;
        case BPAK_HASH_SHA384:
            hash_kind = MBEDTLS_MD_SHA384;
        break;
        case BPAK_HASH_SHA512:
            hash_kind = MBEDTLS_MD_SHA512;
        break;
        default:
            return -BPAK_FAILED;
    }

    return hash_kind;
}

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

    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

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


    if (!key_id || !key_store)
    {
        printf("Error: Missing argument key-id or key-store\n");
        return -BPAK_FAILED;
    }

    struct bpak_package *pkg = NULL;
    uint8_t hash_output[128];

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package\n");
        return -BPAK_FAILED;
    }

    struct bpak_header *h = bpak_pkg_header(pkg);

    FILE *sig_fp = NULL;

    rc = bpak_pkg_sign_init(pkg, bpak_id(key_id), bpak_id(key_store));

    if (rc != BPAK_OK)
        goto err_out;

    /* Set pre-computed signature */
    if (signature_file)
    {
        sig_fp = fopen(signature_file, "r");

        size = fread(sig, 1, sizeof(sig), sig_fp);

        fclose(sig_fp);
        if (bpak_get_verbosity())
            printf("Loaded signature %li bytes\n", size);

    }
    else
    {
        size_t hash_size = sizeof(hash_output);
        bpak_pkg_compute_hash(pkg, hash_output, &hash_size);

        if (bpak_get_verbosity())
        {
            printf("Computed hash: ");
            for (int i = 0; i < hash_size; i++)
                printf("%2.2x", (char ) hash_output[i] & 0xff);
            printf("\n");
        }

        struct bpak_key *sign_key = NULL;

        rc = load_private_key(key_source, &sign_key);

        if (rc != BPAK_OK)
        {
            goto err_out;
        }

        if (bpak_get_verbosity() > 1)
        {
            for (int i = 0; i < sign_key->size; i++)
                printf("%2.2x ", sign_key->data[i] & 0xff);
            printf("\n");
        }

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_pk_init(&ctx);


        rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen(pers));

        if (rc != 0)
        {
            rc = -BPAK_FAILED;
            free(sign_key);
            goto err_out;;
        }


        rc = mbedtls_pk_parse_key(&ctx, sign_key->data, sign_key->size,
                                    NULL, 0);

        if (rc != 0)
        {
            printf("Error: Uknown key type\n");
            free(sign_key);
            rc = -BPAK_FAILED;
            goto err_out;
        }

        rc = mbedtls_pk_sign(&ctx, hash_kind(pkg->header.hash_kind),
                            hash_output, hash_size,
                            sig, &size,
                            mbedtls_ctr_drbg_random, &ctr_drbg);

        if (rc != BPAK_OK)
        {
            printf("Error: Signing failed\n");
        }
    }


    if (bpak_get_verbosity() > 1)
    {
        printf("Signature: ");
        for (int i = 0; i < size; i++)
            printf("%2.2x", sig[i] & 0xff);
        printf("\n");
    }

    rc = bpak_pkg_sign(pkg, sig, size);

err_out:

    bpak_pkg_close(pkg);
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

    const char *pers = "mbedtls_pk_sign";
    mbedtls_pk_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"key",         required_argument, 0,  'k' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvk:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_verify_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'k':
                key_source = (const char *) optarg;
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

    struct bpak_package *pkg = NULL;
    uint8_t hash_output[128];
    uint8_t sig[1024];
    size_t sig_size;

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package\n");
        return -BPAK_FAILED;
    }

    sig_size = sizeof(sig);

    rc = bpak_pkg_read_signature(pkg, sig, &sig_size);

    if (rc != BPAK_OK)
        goto err_out;

    struct bpak_header *h = bpak_pkg_header(pkg);

    size_t hash_size = sizeof(hash_output);
    bpak_pkg_compute_hash(pkg, hash_output, &hash_size);

    if (bpak_get_verbosity() > 1)
    {
        printf("Computed hash: ");
        for (int i = 0; i < hash_size; i++)
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

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&ctx);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));

    if (rc != 0)
    {
        rc = -BPAK_FAILED;
        free(sign_key);
        goto err_out;;
    }


    rc = mbedtls_pk_parse_public_key(&ctx, sign_key->data,
                                        sign_key->size);

    if (rc != 0)
    {
        printf("Error: Uknown key type\n");
        free(sign_key);
        rc = -BPAK_FAILED;
        goto err_out;
    }

    rc = mbedtls_pk_verify(&ctx, hash_kind(pkg->header.hash_kind),
                            hash_output, hash_size,
                            sig, sig_size);

    if (rc != BPAK_OK)
    {
        printf("Error: Verification failed\n");
        rc = -BPAK_FAILED;
        goto err_out;
    }

    printf("Verification OK\n");

err_free_sign_key:
    free(sign_key);
err_out:
    bpak_pkg_close(pkg);
    return rc;
}
