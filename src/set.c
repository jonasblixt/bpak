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
    uint32_t key_id = 0;
    uint32_t keystore_id = 0;
    bool key_id_flag = false;
    bool keystore_id_flag = false;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"meta",        required_argument, 0,  'm' },
        {"from-string", required_argument, 0,  's' },
        {"encoder",     required_argument, 0,  'e' },
        {"key-id",      required_argument, 0,  'k' },
        {"keystore-id", required_argument, 0,  'i' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvp:m:s:e:k:i:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_set_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'k':
                key_id_flag = true;
                if (strncmp(optarg, "0x", 2) == 0) {
                    key_id = strtoul(optarg, NULL, 16);
                } else {
                    key_id = bpak_id(optarg);
                }
            break;
            case 'i':
                keystore_id_flag = true;
                if (strncmp(optarg, "0x", 2) == 0) {
                    keystore_id = strtoul(optarg, NULL, 16);
                } else {
                    keystore_id = bpak_id(optarg);
                }
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

    if (!meta_name && !(key_id_flag || keystore_id_flag))
    {
        printf("Error: Requried argument --meta (or keystore-id and key-id) is missing\n");
        return -1;
    }

    if (!from_string && meta_name)
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

    if (meta_name)
    {
        void *meta = NULL;
        struct bpak_meta_header *meta_header = NULL;

        rc = bpak_get_meta_and_header(h, bpak_id(meta_name), 0, &meta, &meta_header);

        if (rc != BPAK_OK || meta == NULL)
        {
            printf("Error: Could not find '%s'\n", meta_name);
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }

        if (!encoder)
        {
            if (bpak_get_verbosity() > 2)
            {
                printf("Need to grow metadata field with %li bytes\n",
                            strlen(from_string) - meta_header->size);
            }

            struct bpak_header *new_header = malloc(sizeof(struct bpak_header));
            struct bpak_meta_header *meta_tmp = NULL;

            memcpy(new_header, h, sizeof(*h));
            memset(new_header->meta, 0, sizeof(new_header->meta));
            memset(new_header->metadata, 0, sizeof(new_header->metadata));

            bpak_foreach_meta(h, m)
            {
                uint8_t *tmp_ptr = NULL;

                if (!m->id)
                    break;

                if (m->id == bpak_id(meta_name))
                {
                    if (bpak_get_verbosity() > 2)
                    {
                        printf("Updating part %s\n", meta_name);
                    }

                    rc = bpak_add_meta(new_header, m->id, m->part_id_ref,
                                            (void **) &tmp_ptr,
                                            strlen(from_string) + 1);

                    if (rc != BPAK_OK)
                        break;

                    memcpy((void *) tmp_ptr, from_string, strlen(from_string)+1);
                }
                else
                {
                    if (bpak_get_verbosity() > 2)
                    {
                        printf("Copying meta %x, %i\n", m->id, m->size);
                    }
                    rc = bpak_add_meta(new_header, m->id, m->part_id_ref,
                                            (void **) &tmp_ptr,
                                            m->size);

                    if (rc != BPAK_OK)
                        break;

                    memcpy((void *) tmp_ptr, &(h->metadata[m->offset]), m->size);
                }
            }

            free(h);
            h = new_header;

        } else if (strcmp(encoder, "integer") == 0) {
            if (meta_header->size != 8)
            {
                printf("Incorrect meta data length\n");
                rc = -BPAK_FAILED;
                goto err_close_io_out;
            }

            long *val = (uint32_t *) meta;
            (*val) = strtol(from_string, NULL, 0);
        } else if (strcmp(encoder, "id") == 0) {
            if (meta_header->size != 4)
            {
                printf("Incorrect meta data length\n");
                rc = -BPAK_FAILED;
                goto err_close_io_out;
            }
            uint32_t *val = (uint32_t *) meta;
            (*val) = bpak_id(from_string);
        }
        else
        {
            rc = -BPAK_FAILED;
            printf("Error: Unknown encoder\n");
        }
    } else if (key_id_flag || keystore_id_flag) {

        if (key_id_flag) {
            h->key_id = key_id;

            if (bpak_get_verbosity()) {
                printf("Setting key-id to       0x%08x\n", key_id);
            }
        }

        if (keystore_id_flag) {
            h->keystore_id = keystore_id;

            if (bpak_get_verbosity()) {
                printf("Setting keystore-id to  0x%08x\n", keystore_id);
            }
        }
    }
    else
    {
        rc = -BPAK_FAILED;
        printf("Error: Don't know what to do\n");
    }

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
    bpak_io_write(io, h, sizeof(*h));

err_close_io_out:
    bpak_io_close(io);
err_free_header_out:
    free(h);
    return rc;
}
