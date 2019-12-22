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


int action_set(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    uint32_t flags = 0;
    const char *filename = NULL;
    const char *meta_name = NULL;
    const char *from_string = NULL;
    const char *encoder = NULL;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"meta",        required_argument, 0,  'm' },
        {"from_string", required_argument, 0,  's' },
        {"encoder",     required_argument, 0,  'e' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvp:m:s:e:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                printf("Implement me!\n");
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'm':
                meta_name = (const char *) optarg;
            break;
            case 's':
                from_string = (const char *) optarg;
            break;
            case 'e':
                encoder = (const char *) optarg;
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

    if (!meta_name)
    {
        printf("Error: Requried argument --meta is missing\n");
        return -1;
    }

    if (!from_string)
    {
        printf("Error: Missing required option --from_string <...>\n");
        return -1;
    }

    struct bpak_io *io = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    rc = bpak_io_init_file(&io, filename, "r+");

    if (rc != BPAK_OK)
        goto err_free_header_out;

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
    size_t read_bytes = bpak_io_read(io, h, sizeof(*h));

    if (read_bytes != sizeof(*h))
    {
        rc = -BPAK_FAILED;
        printf("Error: Could not read header %li\n", read_bytes);
        goto err_close_io_out;
    }

    rc = bpak_valid_header(h);

    if (rc != BPAK_OK)
    {
        printf("Error: Invalid header. Not a BPAK file?\n");
        goto err_close_io_out;
    }

    void *meta = NULL;
    struct bpak_meta_header *meta_header = NULL;

    rc = bpak_get_meta_and_header(h, id(meta_name), 0, &meta, &meta_header);

    if (rc != BPAK_OK || meta == NULL)
    {
        printf("Error: Could not find '%s'\n", meta_name);
        rc = -BPAK_FAILED;
        goto err_close_io_out;
    }

    if (!encoder)
    {
        if (strlen(from_string) > meta_header->size)
        {
            printf("Input string is to long (> %i)\n", meta_header->size);
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }
    }
    else if (strcmp(encoder, "id") == 0)
    {
        if (meta_header->size != 4)
        {
            printf("Incorrect meta data length\n");
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }
        uint32_t *val = (uint32_t *) meta;
        (*val) = id(from_string);
    }
    else
    {
        rc = -BPAK_FAILED;
        printf("Error: Unknown encoder\n");
    }


    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
    bpak_io_write(io, h, sizeof(*h));

err_close_io_out:
    bpak_io_close(io);
err_free_header_out:
    free(h);
    return rc;
}
