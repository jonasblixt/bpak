/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2020 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/id.h>

#include "bpak_tool.h"


int action_extract(int argc, char **argv)
{
    int opt;
    int rc;
    int long_index = 0;
    bool verbose = false;
    const char *filename = NULL;
    const char *output_filename = NULL;
    uint32_t meta_id = 0;
    uint32_t part_id = 0;
    uint32_t part_id_ref = 0;
    char output_path[16];
    FILE *fp = NULL;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"meta",        required_argument, 0,  'm' },
        {"part",        required_argument, 0,  'p' },
        {"output",      required_argument, 0,  'o' },
        {"part-ref",    required_argument, 0,  'r' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvm:p:o:r:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_extract_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'r':
                if (strncmp(optarg, "0x", 2) == 0) {
                    part_id_ref = strtoul(optarg, NULL, 16);
                } else {
                    part_id_ref = bpak_id(optarg);
                }
            break;
            case 'p':
                if (strncmp(optarg, "0x", 2) == 0) {
                    part_id = strtoul(optarg, NULL, 16);
                } else {
                    part_id = bpak_id(optarg);
                }
            break;
            case 'm':
                if (strncmp(optarg, "0x", 2) == 0) {
                    meta_id = strtoul(optarg, NULL, 16);
                } else {
                    meta_id = bpak_id(optarg);
                }
            break;
            case 'o':
                output_filename = (const char *) optarg;
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

    struct bpak_package pkg;

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package\n");
        return -BPAK_FAILED;
    }

    struct bpak_header *h = bpak_pkg_header(&pkg);

    if (!((meta_id > 0) ^ (part_id > 0)))
    {
        printf("Error: Select either --part or --meta\n");
        rc = -BPAK_FAILED;
        goto err_close_pkg_out;
    }

    if (meta_id)
    {
        struct bpak_meta_header *meta_header = NULL;
        void *data_ptr = NULL;

        rc = bpak_get_meta_and_header(h, meta_id, part_id_ref, &data_ptr,
                                        NULL, &meta_header);

        if (rc != BPAK_OK)
        {
            fprintf(stderr, "Error: Could not find metadata %x\n", meta_id);
            goto err_close_pkg_out;
        }

        if (output_filename != NULL) {
            fp = fopen(output_filename, "w+");

            if (fp == NULL)
            {
                fprintf(stderr, "Error: Could not create '%s'\n",
                                output_filename);
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }

            ssize_t written = fwrite(data_ptr, meta_header->size, 1, fp);

            if (written != 1)
            {
                fprintf(stderr, "Error: write error\n");
                rc = -BPAK_FAILED;
                goto err_close_fp_out;
            }
        } else {
            /* Write to STDOUT */
            if (write(1, data_ptr, meta_header->size) != meta_header->size) {
                fprintf(stderr, "Error: write failed\n");
                rc = -1;
                goto err_close_fp_out;
            }
        }
    }

    if (part_id)
    {
        struct bpak_part_header *part = NULL;
        rc = bpak_get_part(h, part_id, &part);

        if (rc != BPAK_OK)
        {
            fprintf(stderr, "Error: No such part\n");
            rc = -BPAK_FAILED;
            goto err_close_pkg_out;
        }

        uint64_t p_offset = 0;

        p_offset = bpak_part_offset(h, part);

        if (fseek(pkg.fp, p_offset, SEEK_SET) != 0) {
            fprintf(stderr, "Error: Could not seek in stream\n");
            rc = -BPAK_SEEK_ERROR;
            goto err_close_pkg_out;
        }

        if (output_filename) {
            fp = fopen(output_filename, "w+");

            if (fp == NULL)
            {
                fprintf(stderr, "Error: Could not create '%s'\n",
                                output_filename);
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }

            char copy_buffer[1024];
            size_t bytes_to_copy = bpak_part_size(part) - part->pad_bytes;
            size_t chunk = 0;

            while (bytes_to_copy)
            {
                if (bytes_to_copy > sizeof(copy_buffer)) {
                    chunk = sizeof(copy_buffer);
                } else {
                    chunk = bytes_to_copy;
                }

                chunk = fread(copy_buffer, 1, chunk, pkg.fp);
                if (fwrite(copy_buffer, 1, chunk, fp) != chunk) {
                    rc = -BPAK_WRITE_ERROR;
                    goto err_close_pkg_out;
                }

                bytes_to_copy -= chunk;
            }
        } else {
            /* Print to STDOUT */

            char copy_buffer[1024];
            size_t bytes_to_copy = bpak_part_size(part) - part->pad_bytes;
            size_t chunk = 0;

            while (bytes_to_copy)
            {
                if (bytes_to_copy > sizeof(copy_buffer)) {
                    chunk = sizeof(copy_buffer);
                } else {
                    chunk = bytes_to_copy;
                }

                chunk = fread(copy_buffer, 1, chunk, pkg.fp);

                if (write(1, copy_buffer, chunk) != chunk) {
                    fprintf(stderr, "Error: write failed\n");
                    rc = -1;
                    goto err_close_fp_out;
                }
                bytes_to_copy -= chunk;
            }
        }

    }

err_close_fp_out:
    if (fp)
        fclose(fp);
err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
