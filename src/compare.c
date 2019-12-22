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

#include "bpak_tool.h"

int action_compare(int argc, char **argv)
{
    int opt;
    int rc = 0;
    int long_index = 0;
    const char *filename1 = NULL;
    const char *filename2 = NULL;

    struct option long_options[] =
    {
        {"help",      no_argument,       0,  'h' },
        {"verbose",   no_argument,       0,  'v' },
        {0,           0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hv",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_compare_usage();
                return 0;
            break;
            case 'v':
                bpak_inc_verbosity();
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
        filename1 = (const char *) argv[optind++];
    }
    else
    {
        printf("Missing filename argument\n");
        return -1;
    }

    if (optind < argc)
    {
        filename2 = (const char *) argv[optind++];
    }
    else
    {
        printf("Missing filename argument\n");
        return -1;
    }

    struct bpak_io *io1 = NULL;
    struct bpak_io *io2 = NULL;
    struct bpak_header h1, h2;

    rc = bpak_io_init_file(&io1, filename1, "r");

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_io_init_file(&io2, filename2, "r");

    if (rc != BPAK_OK)
        goto err_close_io2_out;

    if (bpak_io_read(io1, &h1, sizeof(h1)) != sizeof(h1))
    {
        printf("Could not read first header\n");
        rc = -BPAK_FAILED;
        goto err_close_io1_out;
    }

    if (bpak_io_read(io2, &h2, sizeof(h2)) != sizeof(h2))
    {
        printf("Could not read second header\n");
        rc = -BPAK_FAILED;
        goto err_close_io1_out;
    }

    printf("BPAK comparison between:\n1: '%s'\n2: '%s'\n", filename1, filename2);
    printf("\n");
    printf("=   : No differance\n");
    printf("+   : Exists in file 2 but not in file 1\n");
    printf("-   : Exists in file 1 but not in file 2\n");
    printf("*   : Exists in both but data differs\n\n");

    char string_output[64];
    struct bpak_header *h1p = &h1;
    struct bpak_header *h2p = &h2;
    char *data1 = NULL;
    char *data2 = NULL;
    bool change;
    bool added;
    bool removed;

    #define RED_CLR "\033[31;1m"
    #define RED_YL "\033[33;1m"
    #define RED_GR "\033[32;1m"
    #define NO_CLR "\033[0m"

    printf("Metadata:\n");
    printf("    ID         Size   Meta ID              Data\n");

    bpak_foreach_meta(h1p, m)
    {
        if (!m->id)
            continue;

        data1 = NULL;
        data2 = NULL;
        change = false;
        added = false;
        removed = false;

        bpak_get_meta(h1p, m->id, (void **) &data1);

        rc = bpak_get_meta(h2p, m->id, (void **) &data2);
        
        /* Missing in file 2? */
        if (rc != BPAK_OK)
            removed = true;

        if (!data1 || !data2)
        {
            removed = true;
        }
        else if (rc == BPAK_OK)
        {
            if (memcmp(data1, data2, m->size) != 0)
                change = true;
        }

        if (change)
        {
            printf(RED_CLR);
            printf("*");
        }
        else if(removed)
        {
            printf(RED_YL);
            printf("-");
        }
        else
        {
            printf("=");
        }

        bpak_meta_to_string(h1p, m, string_output, sizeof(string_output));
        printf("   %8.8x   %-3u    %-20s %s\n", m->id, m->size,
                                bpak_known_id(m->id), string_output);
        printf(NO_CLR);
    }

    /* Check for stuff thats in file 2 but not in 1 */
    bpak_foreach_meta(h2p, m)
    {
        if (!m->id)
            continue;

        data1 = NULL;
        data2 = NULL;
        change = false;
        added = false;
        removed = false;

        bpak_get_meta(h2p, m->id, (void **) &data1);

        rc = bpak_get_meta(h1p, m->id, (void **) &data2);
        
        /* Missing in file 2? */
        if (rc != BPAK_OK)
        {
            printf(RED_YL);
            bpak_meta_to_string(h2p, m, string_output, sizeof(string_output));
            printf("+   %8.8x   %-3u    %-20s %s\n", m->id, m->size,
                                    bpak_known_id(m->id), string_output);
            printf(NO_CLR);
        }
    }

err_close_io1_out:
    bpak_io_close(io1);
err_close_io2_out:
    bpak_io_close(io2);
    return rc;
}
