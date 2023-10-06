/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/crypto.h>

#include "bpak_tool.h"

int action_sign(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *filename = NULL;
    const char *signature_file = NULL;
    const char *key_source = NULL;
    char sig[1024];
    size_t size = sizeof(sig);
    struct bpak_package pkg;
    int rc = 0;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "key", required_argument, 0, 'k' },
        { "signature", required_argument, 0, 'f' },
        { 0, 0, 0, 0 },
    };

    while (
        (opt = getopt_long(argc, argv, "hvk:f:", long_options, &long_index)) !=
        -1) {
        switch (opt) {
        case 'h':
            print_sign_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'k':
            key_source = (const char *)optarg;
            break;
        case 'f':
            signature_file = (const char *)optarg;
            break;
        case '?':
            fprintf(stderr, "Unknown option: %c\n", optopt);
            return -1;
            break;
        case ':':
            fprintf(stderr, "Missing arg for %c\n", optopt);
            return -1;
            break;
        default:
            return -1;
        }
    }

    if (optind < argc) {
        filename = (const char *)argv[optind++];
    } else {
        fprintf(stderr, "Missing filename argument\n");
        return -1;
    }

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Could not open package\n");
        return rc;
    }

    FILE *sig_fp = NULL;

    /* Set pre-computed signature */
    if (signature_file) {
        sig_fp = fopen(signature_file, "r");

        if (sig_fp == NULL) {
            rc = -BPAK_FILE_NOT_FOUND;
            goto err_out;
        }
        size = fread(sig, 1, sizeof(sig), sig_fp);

        fclose(sig_fp);
        if (bpak_get_verbosity()) {
            printf("Loaded signature %zu bytes\n", size);
        }

        rc = bpak_pkg_write_raw_signature(&pkg, (uint8_t *)sig, size);

        if (rc != BPAK_OK)
            goto err_out;
    } else {
        rc = bpak_pkg_sign(&pkg, key_source);

        if (rc != BPAK_OK)
            goto err_out;
    }

err_out:
    bpak_pkg_close(&pkg);
    return rc;
}

int action_verify(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *filename = NULL;
    const char *key_source = NULL;
    const char *keystore_path = NULL;
    struct bpak_package pkg;
    struct bpak_key *key = NULL;

    int rc = 0;

    struct option long_options[] = {
                { "help", no_argument, 0, 'h' },
                { "verbose", no_argument, 0, 'v' },
                { "key", required_argument, 0, 'k' },
                { "keystore", required_argument, 0, 'K' },
                { 0, 0, 0, 0 },
    };

    while ((opt = getopt_long(argc, argv, "hvk:K:", long_options, &long_index)) !=
           -1) {
        switch (opt) {
        case 'h':
            print_verify_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'k':
            key_source = (const char *)optarg;
            break;
        case 'K':
            keystore_path = (const char *)optarg;
            break;
        case '?':
            fprintf(stderr, "Unknown option: %c\n", optopt);
            return -1;
            break;
        case ':':
            fprintf(stderr, "Missing arg for %c\n", optopt);
            return -1;
            break;
        default:
            return -1;
        }
    }

    if (optind < argc) {
        filename = (const char *)argv[optind++];
    } else {
        fprintf(stderr, "Missing filename argument\n");
        return -1;
    }

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Could not open package\n");
        return rc;
    }

    if (key_source != NULL) {
        rc = bpak_crypto_load_public_key(key_source, &key);

        if (rc != BPAK_OK) {
            goto err_close_pkg_out;
        }
    } else if (keystore_path != NULL) {
        rc = bpak_keystore_load_key_from_file(keystore_path,
                                              pkg.header.keystore_id,
                                              pkg.header.key_id,
                                              NULL,
                                              NULL,
                                              &key);

        if (rc != BPAK_OK) {
            goto err_close_pkg_out;
        }
    } else {
        fprintf(stderr, "Either a key file or a keystore must be used to perform verification\n");
        rc = -1;
        goto err_close_pkg_out;
    }

    rc = bpak_pkg_verify(&pkg, key);

    if (rc != BPAK_OK) {
        fprintf(stderr,
                "Verification failed: %i, %s\n",
                rc,
                bpak_error_string(rc));
    } else {
        printf("Verification OK\n");
    }

    free(key);
err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
