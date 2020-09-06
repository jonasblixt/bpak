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
#include <bpak/io.h>
#include <bpak/pkg.h>

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
    char output_path[16];
    FILE *fp = NULL;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"meta",        required_argument, 0,  'm' },
        {"part",        required_argument, 0,  'p' },
        {"output",      required_argument, 0,  'o' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvm:p:o:",
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
            case 'p':
                part_id = bpak_id(optarg);
            break;
            case 'm':
                meta_id = bpak_id(optarg);
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

    struct bpak_package *pkg = NULL;

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package\n");
        return -BPAK_FAILED;
    }

    struct bpak_header *h = bpak_pkg_header(pkg);

    if (!((meta_id > 0) ^ (part_id > 0)))
    {
        printf("Error: Select either --part or --meta\n");
        rc = -BPAK_FAILED;
        goto err_close_pkg_out;
    }

    if (meta_id)
    {
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

        rc = bpak_io_seek(pkg->io, bpak_part_offset(h, part), BPAK_IO_SEEK_SET);

        if (rc != BPAK_OK)
        {
            fprintf(stderr, "Error: Could not seek in stream\n");
        }

        snprintf(output_path, sizeof(output_path), "%08x", part_id);

        char *path_str = NULL;

        if (output_filename)
            path_str = output_filename;
        else
            path_str = output_path;

        fp = fopen(path_str, "w+");

        if (fp == NULL)
        {
            fprintf(stderr, "Error: Could not create '%s'\n",
                            path_str);
            rc = -BPAK_FAILED;
            goto err_close_pkg_out;
        }

        char copy_buffer[1024];
        size_t bytes_to_copy = bpak_part_size(part);
        size_t chunk = 0;

        while (bytes_to_copy)
        {
            chunk = bpak_io_read(pkg->io, copy_buffer, sizeof(copy_buffer));
            fwrite(copy_buffer, chunk, 1, fp);
            bytes_to_copy -= chunk;
        }

    }

err_close_fp_out:
    fclose(fp);
err_close_pkg_out:
    bpak_pkg_close(pkg);
    return rc;
}
