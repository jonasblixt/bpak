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

#include "bpak_tool.h"


int action_transport(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    uint32_t flags = 0;
    const char *filename = NULL;
    const char *origin_file = NULL;
    const char *output_file = NULL;
    const char *encoder_alg = NULL;
    const char *decoder_alg = NULL;
    bool add_flag = false;
    bool encode_flag = false;
    bool decode_flag = false;
    bool output_header_last = false;
    int rc = 0;
    int rate_limit = 0;
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
        {"output-header-last", no_argument,0,  'H' },
        {"rate-limit",  required_argument, 0,  'R' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvao:s:O:e:d:EGr:HR:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_transport_usage();
                return 0;
            case 'H':
                output_header_last = true;
            break;
            case 'R':
                rate_limit = strtoul(optarg, 0, 0);
            break;
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

    struct bpak_package *input = NULL;
    struct bpak_package *output = NULL;
    struct bpak_package *origin = NULL;

    rc = bpak_pkg_open(&input, filename, "rb+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package %s\n", filename);
        return -BPAK_FAILED;
    }

    struct bpak_header *h = bpak_pkg_header(input);

    if (origin_file)
    {
        rc = bpak_pkg_open(&origin, origin_file, "rb+");

        if (rc != BPAK_OK)
        {
            printf("Error: Could not open package %s\n", origin_file);
            return -BPAK_FAILED;
        }
    }

    if ((encode_flag || decode_flag) && !output_file) {
        printf("Error: No output file specified\n");
        rc = -1;
        goto err_out;
    }

    if (encode_flag || decode_flag) {
        if (output_header_last) {
            rc = bpak_pkg_open(&output, output_file, "rb+");
        } else {
            rc = bpak_pkg_open(&output, output_file, "wb+");
        }

        if (rc != BPAK_OK)
        {
            printf("Error: Could not open output file %s\n", output_file);
            goto err_out;
        }
    }

    if (encode_flag) {
        rc = bpak_pkg_transport_encode(input, output, origin, rate_limit);
    } else if(decode_flag) {
        rc = bpak_pkg_transport_decode(input, /* Input package or 'patch' */
                                       output,
                                       origin, /* Origin data to use for patch operation*/
                                       rate_limit, /* Rate limit */
                                       output_header_last);
    } else if (add_flag && encoder_alg && decoder_alg) {
        rc = bpak_pkg_add_transport(input, part_ref,
                                         bpak_id(encoder_alg),
                                         bpak_id(decoder_alg));
    } else {
        rc = -BPAK_FAILED;
        printf("Error: Unknown command");
    }

    if (rc != BPAK_OK) {
        rc = -BPAK_FAILED;
        printf("Error: Transport encoding/decoding failed\n");
    }

err_out:
    bpak_pkg_close(input);

    if (origin)
        bpak_pkg_close(origin);

    return rc;
}
