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
    const char *filename = NULL;
    const char *output_filename = NULL;
    bpak_id_t meta_id = 0;
    bpak_id_t part_id = 0;
    bpak_id_t part_id_ref = 0;
    FILE *fp = NULL;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "meta", required_argument, 0, 'm' },
        { "part", required_argument, 0, 'p' },
        { "output", required_argument, 0, 'o' },
        { "part-ref", required_argument, 0, 'r' },
        { 0, 0, 0, 0 },
    };

    while ((opt = getopt_long(argc,
                              argv,
                              "hvm:p:o:r:",
                              long_options,
                              &long_index)) != -1) {
        switch (opt) {
        case 'h':
            print_extract_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'r':
            part_id_ref = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'p':
            part_id = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'm':
            meta_id = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'o':
            output_filename = (const char *)optarg;
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

    if (!((meta_id > 0) ^ (part_id > 0))) {
        fprintf(stderr, "Error: Select either --part or --meta\n");
        return -BPAK_FAILED;
    }

    struct bpak_package pkg;

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Could not open package\n");
        return rc;
    }

    struct bpak_header *h = bpak_pkg_header(&pkg);

    if (meta_id) {
        struct bpak_meta_header *meta_header = NULL;
        void *data_ptr = NULL;

        rc = bpak_get_meta(h,
                           meta_id,
                           part_id_ref,
                           &meta_header);

        if (rc != BPAK_OK) {
            fprintf(stderr, "Error: Could not find metadata %x\n", meta_id);
            goto err_close_pkg_out;
        }

        data_ptr = bpak_get_meta_ptr(h, meta_header, void);

        if (output_filename != NULL) {
            fp = fopen(output_filename, "w+");

            if (fp == NULL) {
                fprintf(stderr,
                        "Error: Could not create '%s'\n",
                        output_filename);
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }
        } else {
            fp = stdout;
        }

        ssize_t written = fwrite(data_ptr, 1, meta_header->size, fp);

        if (written != meta_header->size) {
            fprintf(stderr, "Error: write error\n");
            rc = -BPAK_WRITE_ERROR;
            goto err_close_fp_out;
        }
    }

    if (part_id) {
        rc = bpak_pkg_extract_file(&pkg, part_id, output_filename);
    }

err_close_fp_out:
    if ((fp != stdout) && (fp != NULL)) {
        fclose(fp);
    }
err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
