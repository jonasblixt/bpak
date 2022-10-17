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

int action_add(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    uint32_t flags = 0;
    char metadata_input[BPAK_METADATA_BYTES] = { 0 };
    size_t metadata_input_length = 0;
    const char *filename = NULL;
    const char *part_name = NULL;
    const char *meta_name = NULL;
    const char *from_file = NULL;
    const char *from_string = NULL;
    const char *part_ref = NULL;
    const char *encoder = NULL;
    int rc = 0;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "part", required_argument, 0, 'p' },
        { "meta", required_argument, 0, 'm' },
        { "from-file", required_argument, 0, 'f' },
        { "from-string", required_argument, 0, 's' },
        { "encoder", required_argument, 0, 'e' },
        { "set-flag", required_argument, 0, 'F' },
        { "part-ref", required_argument, 0, 'r' },
        { 0, 0, 0, 0 },
    };

    while ((opt = getopt_long(argc,
                              argv,
                              "hvp:m:f:s:e:F:r:",
                              long_options,
                              &long_index)) != -1) {
        switch (opt) {
        case 'h':
            print_add_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'p':
            part_name = (const char *)optarg;
            break;
        case 'm':
            meta_name = (const char *)optarg;
            break;
        case 'r':
            part_ref = (const char *)optarg;
            break;
        case 'f':
            from_file = (const char *)optarg;
            break;
        case 's':
            from_string = (const char *)optarg;
            break;
        case 'e':
            encoder = (const char *)optarg;
            break;
        case 'F':
            if (strcmp(optarg, "dont-hash") == 0)
                flags |= BPAK_FLAG_EXCLUDE_FROM_HASH;
            else {
                fprintf(stderr, "Unknown flag '%s'\n", optarg);
                return -1;
            }
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

    if (!part_name && !meta_name) {
        fprintf(stderr,
                "Error: Requried argument --part or --meta is missing\n");
        return -1;
    }

    if (!from_string && !from_file) {
        fprintf(stderr,
                "Error: either --from_string must be used or --from_file\n");
        return -1;
    }

    struct bpak_package pkg;

    rc = bpak_pkg_open(&pkg, filename, "r+");

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Could not open package\n");
        return rc;
    }

    struct bpak_header *h = bpak_pkg_header(&pkg);

    if (meta_name) {
        unsigned char *meta_data = NULL;
        uint32_t part_ref_id = 0;

        if (part_ref)
            part_ref_id = bpak_id(part_ref);

        if (from_string) {
            metadata_input_length = strlen(from_string) + 1;
            if (metadata_input_length > sizeof(metadata_input)) {
                rc = -BPAK_NO_SPACE_LEFT;
                goto err_close_pkg_out;
            }
            strncpy(metadata_input, from_string, metadata_input_length);
        } else if (from_file) {
            FILE *meta_in_fp = fopen(from_file, "r");
            if (meta_in_fp == NULL) {
                fprintf(stderr, "Error: Could not open '%s'\n", from_file);
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }

            metadata_input_length = fread(metadata_input, 1,
                                    sizeof(metadata_input), meta_in_fp);

            fclose(meta_in_fp);

            if (metadata_input_length == 0) {
                fprintf(stderr, "Error: Read zero bytes\n");
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }
        } else {
            fprintf(stderr, "Error: No input supplied with --from-string or --from-file\n");
            rc = -BPAK_FAILED;
            goto err_close_pkg_out;
        }

        if (encoder) {
            if (strcmp(encoder, "uuid") == 0) {
                uuid_t uu;

                rc = uuid_parse(metadata_input, uu);

                if (rc != 0) {
                    rc = -BPAK_FAILED;
                    fprintf(stderr, "Error: Could not convert UUID string\n");
                    goto err_close_pkg_out;
                }

                rc = bpak_add_meta(h,
                                   bpak_id(meta_name),
                                   part_ref_id,
                                   (void **)&meta_data,
                                   16);

                if (rc != BPAK_OK) {
                    fprintf(stderr, "Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, uu, 16);

                if (bpak_get_verbosity()) {
                    printf("Adding %s <%s>\n", meta_name, from_string);
                }
            } else if (strcmp(encoder, "integer") == 0) {
                long value = strtol(metadata_input, NULL, 0);

                rc = bpak_add_meta(h,
                                   bpak_id(meta_name),
                                   part_ref_id,
                                   (void **)&meta_data,
                                   sizeof(value));

                if (rc != BPAK_OK) {
                    fprintf(stderr, "Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if (bpak_get_verbosity()) {
                    printf("Adding %s <0x%lx>\n", meta_name, value);
                }
            } else if (strcmp(encoder, "id") == 0) {
                uint32_t value = bpak_id(metadata_input);

                rc = bpak_add_meta(h,
                                   bpak_id(meta_name),
                                   part_ref_id,
                                   (void **)&meta_data,
                                   sizeof(value));

                if (rc != BPAK_OK) {
                    fprintf(stderr, "Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if (bpak_get_verbosity()) {
                    fprintf(stderr, "Adding %s <%x>\n", meta_name, value);
                }
            } else {
                fprintf(stderr, "Error: Unknown encoder\n");
                rc = -BPAK_NOT_SUPPORTED;
                goto err_close_pkg_out;
            }
        } else {
            if (bpak_get_verbosity())
                printf("Adding metadata with id '%s'\n", meta_name);

            rc = bpak_add_meta(h,
                               bpak_id(meta_name),
                               part_ref_id,
                               (void **)&meta_data,
                               metadata_input_length);

            if (rc != BPAK_OK) {
                fprintf(stderr, "Error: Could not add meta data\n");
                goto err_close_pkg_out;
            }

            memcpy(meta_data, metadata_input, metadata_input_length);
        }

        if (bpak_get_verbosity() > 2)
            printf("Meta data array pointer = %p\n", meta_data);

        rc = bpak_pkg_write_header(&pkg);

        if (rc != BPAK_OK) {
            fprintf(stderr, "Error: Could not write header\n");
            goto err_close_pkg_out;
        }
    } else if (part_name && !encoder) {
        rc = bpak_pkg_add_file(&pkg, from_file, part_name, flags);

    } else if (part_name && strcmp(encoder, "key") == 0) {
        rc = bpak_pkg_add_key(&pkg, from_file, part_name, flags);
    } else if (strcmp(encoder, "merkle") == 0) {
        if (bpak_get_verbosity())
            printf("Writing filesystem...\n");

        rc = bpak_pkg_add_file_with_merkle_tree(&pkg,
                                                from_file,
                                                part_name,
                                                flags);
        if (rc != BPAK_OK)
            goto err_close_pkg_out;

    } else {
        fprintf(stderr, "Error: Unknown command\n");
        rc = -BPAK_FAILED;
    }

err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
