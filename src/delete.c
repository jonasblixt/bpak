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

#include "uuid.h"
#include "bpak_tool.h"

int action_delete(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *filename = NULL;
    bpak_id_t part_id = 0;
    bool delete_all = false;
    bool keep_metadata = false;
    int rc = 0;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "part", required_argument, 0, 'p' },
        { "all", no_argument, 0, 'a' },
        { "keep-meta", no_argument, 0, 'k' },
        { 0, 0, 0, 0 },
    };

    while ((opt = getopt_long(argc,
                              argv,
                              "hvp:ak",
                              long_options,
                              &long_index)) != -1) {
        switch (opt) {
        case 'h':
            print_delete_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'p':
            part_id = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'a':
            delete_all = true;
            break;
        case 'k':
            keep_metadata = true;
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

    if (part_id == 0 && !delete_all) {
        fprintf(stderr, "Error: Select either --part or --all\n");
        return -BPAK_FAILED;
    }

    struct bpak_package pkg;
    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Could not open package\n");
        return rc;
    }

    if (delete_all) {
        rc = bpak_pkg_delete_all_parts(&pkg, !keep_metadata);
    } else if (part_id > 0) {
        rc = bpak_pkg_delete_part(&pkg, part_id, !keep_metadata);
    } else {
        fprintf(stderr, "Error: Unknown command\n");
        rc = -BPAK_FAILED;
    }

    bpak_pkg_close(&pkg);
    return rc;

}
