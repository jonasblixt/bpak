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

#include "bpak_tool.h"

static int calc_hash(struct bpak_header *h, struct bpak_io *io,
                    char *output, size_t *size)
{
    int rc;
    struct bpak_hash_context hash;

    rc = bpak_hash_init(&hash, h->hash_kind);

    if (rc != BPAK_OK)
        return rc;

    /* Zero out signature if it exists */
    bpak_foreach_meta(h, m)
    {
        if (m->id == id("bpak-signature"))
        {
            uint8_t *ptr = &h->metadata[m->offset];
            memset(ptr, 0, m->size);
            memset(m, 0, sizeof(*m));
        }
    }

    bpak_hash_update(&hash, h, sizeof(*h));

    char hash_buffer[512];
    char hash_output[64];

    bpak_io_seek(io, sizeof(*h), BPAK_IO_SEEK_SET);

    bpak_foreach_part(h, p)
    {
        size_t bytes_to_read = bpak_part_size(p);
        size_t chunk = 0;

        if (!p->id)
            continue;

        if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
        {
            bpak_io_seek(io, bpak_part_size(p), BPAK_IO_SEEK_FWD);
            continue;
        }

        do
        {
            chunk = (bytes_to_read > sizeof(hash_buffer))?
                        sizeof(hash_buffer):bytes_to_read;

            bpak_io_read(io, hash_buffer, chunk);
            bpak_hash_update(&hash, hash_buffer, chunk);
            bytes_to_read -= chunk;
        } while (bytes_to_read);
    }

    bpak_hash_out(&hash, output, *size);
    *size = hash.size;

    return rc;
}

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

    struct bpak_io *io = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    if (!h)
        return -BPAK_FAILED;

    rc = bpak_io_init_file(&io, filename, "rb");

    if (rc != BPAK_OK)
        goto err_free_header_out;

    size_t read_bytes = bpak_io_read(io, h, sizeof(*h));

    if (read_bytes != sizeof(*h))
    {
        rc = -BPAK_FAILED;
        goto err_free_io_out;
    }

    if (meta_name)
    {
        rc = -BPAK_FAILED;

        bpak_foreach_meta(h, m)
        {
            if (m->id == id(meta_name))
            {
                printf("Found 0x%x, %i bytes\n", m->id, m->size);
                rc = BPAK_OK;
                break;
            }
        }

        if (rc != BPAK_OK)
        {
            printf("Error: Could not find meta '%s'\n", meta_name);
        }

        goto err_free_io_out;
    }

    if (part_name)
    {
        rc = -BPAK_FAILED;

        bpak_foreach_part(h, p)
        {
            if (p->id == id(part_name))
            {
                printf("Found 0x%x, %li bytes\n", p->id, p->size);
                rc = BPAK_OK;
                break;
            }
        }

        if (rc != BPAK_OK)
        {
            printf("Error: Could not find part '%s'\n", part_name);
        }

        goto err_free_io_out;
    }

    if (binary_hash_output)
    {
        rc = calc_hash(h, io, hash_output, &hash_size);

        for (int i = 0; i < hash_size; i++)
            printf("%c", hash_output[i]);
        goto err_free_io_out;
    }

    printf("BPAK File: %s\n", filename);
    printf("\n");
    printf("Hash:      %s\n", bpak_hash_kind(h->hash_kind));
    printf("Signature: %s\n", bpak_signature_kind(h->signature_kind));

    printf("\nMetadata:\n");
    printf("    ID         Size   Meta ID              Part Ref   Data\n");

    char string_output[65];

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

    rc = calc_hash(h, io, hash_output, &hash_size);

    printf("\nHash: ");
    for (int i = 0; i < hash_size; i++)
        printf("%2.2x", (char ) hash_output[i] & 0xff);
    printf("\n");

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

        size_t installed_size = 0;
        size_t transport_size = 0;

        bpak_foreach_part(h, p)
        {
            if (p->flags & BPAK_FLAG_TRANSPORT)
                transport_size += p->transport_size;
            else
                transport_size += p->size;
            installed_size += p->size + p->pad_bytes;
        }
        transport_size += sizeof(struct bpak_header);
        printf("Transport size: %li bytes\n", transport_size);
        printf("Installed size: %li bytes\n", installed_size);
    }

err_free_io_out:
    bpak_io_close(io);
err_free_header_out:
    free(h);
    return rc;
}
