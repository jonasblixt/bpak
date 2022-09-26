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
#include <bpak/id.h>

#include "bpak_tool.h"


int action_transport(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *filename = NULL;
    const char *origin_file = NULL;
    const char *output_file = NULL;
    const char *encoder_alg = NULL;
    const char *decoder_alg = NULL;
    bool add_flag = false;
    bool encode_flag = false;
    bool decode_flag = false;
    int rc = 0;
    uint32_t part_ref = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"add",         no_argument,       0,  'a' },
        {"origin",      required_argument, 0,  'O' },
        {"output",      required_argument, 0,  'o' },
        {"encoder",     required_argument, 0,  'e' },
        {"decoder",     required_argument, 0,  'd' },
        {"encode",      no_argument,       0,  'E' },
        {"decode",      no_argument,       0,  'D' },
        {"part-ref",    required_argument, 0,  'r' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvao:s:O:e:d:EGr:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_transport_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'a':
                add_flag = true;
            break;
            case 'E':
                encode_flag = true;
            break;
            case 'r':
                if (strncmp(optarg, "0x", 2) == 0) {
                    part_ref = strtoul(optarg, NULL, 16);
                } else {
                    part_ref = bpak_id(optarg);
                }
            break;
            case 'O':
                origin_file = (const char *) optarg;
            break;
            case 'o':
                output_file = (const char *) optarg;
            break;
            case 'e':
                encoder_alg = (const char *) optarg;
            break;
            case 'd':
                decoder_alg = (const char *) optarg;
            break;
            case 'D':
                decode_flag = true;
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

    if (encode_flag + add_flag + decode_flag > 1)
    {
        printf("Error: Only one of --add, --encode or --decode is allowed\n");
        return -1;
    }

    struct bpak_package input;
    struct bpak_package output;
    struct bpak_package origin;

    rc = bpak_pkg_open(&input, filename, "rb+");

    if (rc != BPAK_OK) {
        printf("Error: Could not open package %s\n", filename);
        return rc;
    }

    if (origin_file) {
        rc = bpak_pkg_open(&origin, origin_file, "rb+");

        if (rc != BPAK_OK) {
            printf("Error: Could not open package %s\n", origin_file);
            return rc;
        }
    }

    if ((encode_flag || decode_flag) && !output_file) {
        printf("Error: No output file specified\n");
        rc = -1;
        goto err_out;
    }

    if (encode_flag || decode_flag) {
        rc = bpak_pkg_open(&output, output_file, "wb+");

        if (rc != BPAK_OK)
        {
            printf("Error: Could not open output file %s\n", output_file);
            goto err_out;
        }
    }

    if (encode_flag) {
        rc = bpak_pkg_transport_encode(&input, &output, &origin);
    } else if(decode_flag) {
        rc = bpak_pkg_transport_decode(&input, /* Input package or 'patch' */
                                       &output,
                                       &origin); /* Origin data to use for patch operation*/
    } else if (add_flag && encoder_alg && decoder_alg) {
        rc = bpak_add_transport_meta(&input.header, part_ref,
                                         bpak_id(encoder_alg),
                                         bpak_id(decoder_alg));

        if (rc != BPAK_OK) {
            fprintf(stderr, "Error: Could not add transport meta data\n");
            goto err_out;
        }

        rc = bpak_pkg_write_header(&input);
    } else {
        rc = -BPAK_FAILED;
        printf("Error: Unknown command");
    }

    if (rc != BPAK_OK) {
        printf("Error: Transport encoding/decoding failed\n");
    }

err_out:
    bpak_pkg_close(&input);

    if (origin_file) {
        bpak_pkg_close(&origin);
    }

    return rc;
}
