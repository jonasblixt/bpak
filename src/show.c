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

int action_show(int argc, char **argv)
{
    int opt;
    int rc = 0;
    int long_index = 0;
    const char *filename = NULL;
    const char *part_name = NULL;
    const char *meta_name = NULL;
    bool binary_hash_output = false;
    char hash_output[64];
    size_t hash_size = sizeof(hash_output);
    char string_output[128];

    struct option long_options[] =
    {
        {"help",      no_argument,       0,  'h' },
        {"verbose",   no_argument,       0,  'v' },
        {"meta",      required_argument, 0,  'm' },
        {"part",      required_argument, 0,  'p' },
        {"hash",      no_argument,       0,  'H' },
        {0,           0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvm:p:H",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_show_usage();
                return 0;
            break;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'p':
                part_name = (const char *) optarg;
            break;
            case 'm':
                meta_name = (const char *) optarg;
            break;
            case 'H':
                binary_hash_output = true;
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

    rc = bpak_pkg_open(&pkg, filename, "rb");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open package\n");
        return -BPAK_FAILED;
    }

    struct bpak_header *h = bpak_pkg_header(pkg);
    memset(string_output, 0, sizeof(string_output));

    if (meta_name)
    {
        rc = -BPAK_FAILED;

        bpak_foreach_meta(h, m)
        {
            if (m->id == bpak_id(meta_name))
            {
                /*printf("Found 0x%x, %i bytes\n", m->id, m->size);*/

                if (part_name)
                    if (bpak_id(part_name) != m->part_id_ref)
                        continue;

                bpak_meta_to_string(h, m, string_output, sizeof(string_output));
                if (strlen(string_output))
                    printf("%s\n", string_output);
                
                rc = BPAK_OK;
                break;
            }
        }

        if (rc != BPAK_OK)
        {
            printf("Error: Could not find meta '%s'\n", meta_name);
        }

        goto err_pkg_close;
    }

    if (part_name)
    {
        rc = -BPAK_FAILED;

        bpak_foreach_part(h, p)
        {
            if (p->id == bpak_id(part_name))
            {
                printf("Found 0x%x, %li bytes\n", p->id, p->size);
                rc = BPAK_OK;
                break;
            }
        }

        if (rc != BPAK_OK)
        {
            printf("Error: Could not find part '%s'\n", part_name);
            goto err_pkg_close;
        }
    }

    if (binary_hash_output)
    {
        hash_size = sizeof(hash_output);
        bpak_pkg_compute_hash(pkg, hash_output, &hash_size);

        for (int i = 0; i < hash_size; i++)
            printf("%c", hash_output[i]);
        goto err_pkg_close;
    }

    printf("BPAK File: %s\n", filename);
    printf("\n");
    printf("Hash:      %s\n", bpak_hash_kind(h->hash_kind));
    printf("Signature: %s\n", bpak_signature_kind(h->signature_kind));

    printf("\nMetadata:\n");
    printf("    ID         Size   Meta ID              Part Ref   Data\n");


    bpak_foreach_meta(h, m)
    {
        if (m->id)
        {
            bpak_meta_to_string(h, m, string_output, sizeof(string_output));
            printf("    %8.8x   %-3u    %-20s ", m->id, m->size,
                         bpak_known_id(m->id));

            if (m->part_id_ref)
                printf("%8.8x", m->part_id_ref);
            else
                printf("        ");
            printf("   %s", string_output);
            printf("\n");
        }
    }

    printf("\nParts:\n");
    printf("    ID         Size         Z-pad  Flags          Transport Size\n");

    char flags_str[9] = "--------";

    bpak_foreach_part(h, p)
    {
        if (p->id)
        {
            if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
                flags_str[0] = 'h';
            else
                flags_str[0] = '-';

            if (p->flags & BPAK_FLAG_TRANSPORT)
                flags_str[1] = 'T';
            else
                flags_str[1] = '-';

            printf("    %8.8x   %-12lu %-3u    %s",p->id, p->size, p->pad_bytes,
                                                flags_str);

            if (p->flags & BPAK_FLAG_TRANSPORT)
                printf("       %-12lu", p->transport_size);
            else
                printf("       %-12lu", p->size);

            printf("\n");
        }
    }


    hash_size = sizeof(hash_output);
    bpak_pkg_compute_hash(pkg, hash_output, &hash_size);

    char hash_str[128];
    bpak_bin2hex(hash_output, hash_size, hash_str, sizeof(hash_str));
    printf("\nHash: %s\n", hash_str);

    if (bpak_get_verbosity())
    {
        uint32_t meta_size = 0;
        uint8_t no_of_meta_headers = 0;

        bpak_foreach_meta(h, m)
        {
            meta_size += m->size;
            no_of_meta_headers++;
        }

        printf ("Metadata usage: %i/%li bytes\n", meta_size,
                    sizeof(h->metadata));

        printf("Transport size: %li bytes\n", bpak_pkg_size(pkg));
        printf("Installed size: %li bytes\n", bpak_pkg_installed_size(pkg));
    }
err_pkg_close:
    bpak_pkg_close(pkg);
    return rc;
}
