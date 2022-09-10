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
#include <uuid.h>

#include <bpak/pkg.h>
#include <bpak/id.h>
#include "bpak_tool.h"

int action_add(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    uint32_t flags = 0;
    const char *filename = NULL;
    const char *part_name = NULL;
    const char *meta_name = NULL;
    const char *from_file = NULL;
    const char *from_string = NULL;
    const char *part_ref = NULL;
    const char *encoder = NULL;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"part",        required_argument, 0,  'p' },
        {"meta",        required_argument, 0,  'm' },
        {"from-file",   required_argument, 0,  'f' },
        {"from-string", required_argument, 0,  's' },
        {"encoder",     required_argument, 0,  'e' },
        {"set-flag",    required_argument, 0,  'F' },
        {"part-ref",    required_argument, 0,  'r' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvp:m:f:s:e:F:r:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_add_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'p':
                part_name = (const char *) optarg;
            break;
            case 'm':
                meta_name = (const char *) optarg;
            break;
            case 'r':
                part_ref = (const char *) optarg;
            break;
            case 'f':
                from_file = (const char *) optarg;
            break;
            case 's':
                from_string = (const char *) optarg;
            break;
            case 'e':
                encoder = (const char *) optarg;
            break;
            case 'F':
                if (strcmp(optarg, "dont-hash") == 0)
                    flags |= BPAK_FLAG_EXCLUDE_FROM_HASH;
                else
                {
                    printf("Unknown flag '%s'\n", optarg);
                    return -1;
                }
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

    if (!part_name && !meta_name)
    {
        printf("Error: Requried argument --part or --meta is missing\n");
        return -1;
    }

    if (!from_string && !from_file)
    {
        printf("Error: either --from_string must be used or --from_file\n");
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

    if (meta_name)
    {
        unsigned char *meta_data = NULL;
        uint32_t part_ref_id = 0;

        if (part_ref)
            part_ref_id = bpak_id(part_ref);

        if (!from_string)
        {
            printf("Error: No input supplied with --from-string\n");
            rc = -BPAK_FAILED;
            goto err_close_pkg_out;
        }

        if (encoder)
        {
            if (strcmp(encoder, "uuid") == 0)
            {
                uuid_t uu;
                char uuid_text[37];
                rc = uuid_parse(from_string, uu);

                if (rc != 0)
                {
                    rc = -BPAK_FAILED;
                    printf("Error: Could not convert UUID string\n");
                    goto err_close_pkg_out;
                }

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                                (void **) &meta_data, 16);

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, uu, 16);

                if(bpak_get_verbosity())
                {
                    uuid_unparse(meta_data, uuid_text);
                    printf("Adding %s <%s>\n", meta_name, uuid_text);
                }
            }
            else if (strcmp(encoder, "integer") == 0)
            {
                long value = strtol(from_string, NULL, 0);

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                        (void **) &meta_data, sizeof(value));

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if(bpak_get_verbosity())
                {
                    printf("Adding %s <0x%lx>\n", meta_name, value);
                }
            }
            else if (strcmp(encoder, "id") == 0)
            {
                uint32_t value = bpak_id(from_string);

                rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                        (void **) &meta_data, sizeof(value));

                if (rc != BPAK_OK)
                {
                    printf("Error: Could not add meta data\n");
                    goto err_close_pkg_out;
                }

                memcpy(meta_data, &value, sizeof(value));

                if(bpak_get_verbosity())
                {
                    printf("Adding %s <%x>\n", meta_name, value);
                }
            }
            else
            {
                printf("Error: Unknown encoder\n");
                rc = -BPAK_FAILED;
                goto err_close_pkg_out;
            }
        }
        else
        {
            if (bpak_get_verbosity())
                printf("Adding '%s' with id '%s'\n", from_string, meta_name);

            rc = bpak_add_meta(h, bpak_id(meta_name), part_ref_id,
                                (void **) &meta_data, strlen(from_string) + 1);

            if (rc != BPAK_OK)
            {
                printf("Error: Could not add meta data\n");
                goto err_close_pkg_out;
            }

            memcpy(meta_data, from_string, strlen(from_string));
        }

        if (bpak_get_verbosity() > 2)
            printf("Meta data array pointer = %p\n", meta_data);

        rc = bpak_pkg_write_header(&pkg);

        if (rc != BPAK_OK)
        {
            fprintf(stderr, "Error: Could not write header\n");
            goto err_close_pkg_out;
        }
    }
    else if (part_name && !encoder)
    {
        rc = bpak_pkg_add_file(&pkg, from_file, part_name, flags);

    }
    else if (part_name && strcmp(encoder, "key") == 0)
    {
        rc = bpak_pkg_add_key(&pkg, from_file, part_name, flags);
    }
    else if (strcmp(encoder, "merkle") == 0)
    {
#ifdef BPAK_BUILD_MERKLE
        if (bpak_get_verbosity())
            printf("Writing filesystem...\n");

        rc = bpak_pkg_add_file_with_merkle_tree(&pkg, from_file, part_name, flags);
#else
        rc = -BPAK_NOT_SUPPORTED;
#endif
        if (rc != BPAK_OK)
            goto err_close_pkg_out;

    }
    else
    {
        printf("Error: Unknown command\n");
        rc = -BPAK_FAILED;
    }

err_close_pkg_out:
    bpak_pkg_close(&pkg);
    return rc;
}
