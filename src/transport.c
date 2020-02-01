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

static int transport_process(struct bpak_transport_meta *tm,
                                 struct bpak_header *h,
                                 uint32_t part_ref_id,
                                 struct bpak_io *io,
                                 struct bpak_io *origin,
                                 uint8_t *state_buffer,
                                 size_t size,
                                 bool decode_flag)
{
    int rc;
    struct bpak_alg_instance ins;
    struct bpak_part_header *p = NULL;
    struct bpak_io *tmp;
    struct bpak_alg *alg = NULL;
    uint64_t bytes_to_copy = 0;
    size_t chunk_sz = 0;
    size_t read_bytes = 0;
    size_t written_bytes = 0;
    uint32_t alg_id = 0;

    rc = bpak_get_part(h, part_ref_id, &p);

    if (rc != BPAK_OK)
    {
        printf("Error could not get part with ref %x\n", part_ref_id);
        return rc;
    }

    if (decode_flag)
        alg_id = tm->alg_id_decode;
    else
        alg_id = tm->alg_id_encode;

    rc = bpak_alg_get(alg_id, &alg);

    if (rc != BPAK_OK || !alg)
    {
        printf("Error: Unknown algorithm: %8.8x\n", alg_id);
        return rc;
    }

    if (bpak_get_verbosity())
        printf("Processing part %8.8x using '%s' [%8.8x]\n", part_ref_id,
                                alg->name, alg_id);

    /* Already processed for transport ?*/
    if ((p->flags & BPAK_FLAG_TRANSPORT) && (!decode_flag))
        return BPAK_OK;

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);

    rc = bpak_io_init_random_file(&tmp);

    if (rc != BPAK_OK)
        goto err_close_io_out;

    if (bpak_get_verbosity() > 1)
        printf("Created temporary file: %s\n", bpak_io_filename(tmp));

    /* Copy everyting up until the part we are interested in */

    bpak_io_write(tmp, h, sizeof(*h));

    bpak_foreach_part(h, part)
    {
        if (part->id == p->id)
            break;
        if (!part->id)
            continue;

        bpak_io_seek(io, bpak_part_offset(h, part), BPAK_IO_SEEK_SET);

        bytes_to_copy = bpak_part_size(part);

        while (bytes_to_copy)
        {
            chunk_sz = (bytes_to_copy > size)?size:bytes_to_copy;
            bpak_io_read(io, state_buffer, chunk_sz);
            bpak_io_write(tmp, state_buffer, chunk_sz);
            bytes_to_copy -= chunk_sz;
        }
    }

    if (bpak_get_verbosity())
        printf("Initializing alg, input size %li bytes\n", bpak_part_size(p));

    bpak_io_seek(io, bpak_part_offset(h, p), BPAK_IO_SEEK_SET);

    rc = bpak_alg_init(&ins, alg_id, p, h, state_buffer, size, io, tmp, origin);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not initialize algorithm %8.8x\n", alg_id);
        return -BPAK_FAILED;
    }

    while (!bpak_alg_done(&ins))
    {
        rc = bpak_alg_process(&ins);

        if (rc != BPAK_OK)
        {
            printf("Error: processing failed\n");
            break;
        }
    }

    if (rc != BPAK_OK)
        goto err_close_io_out;

    bpak_alg_free(&ins);

    if (bpak_get_verbosity())
        printf("Done processing, output size %li bytes\n", ins.output_size);

    /* Position input stream at the end of the part in intereset */
    rc = bpak_io_seek(io, bpak_part_offset(h, p) + bpak_part_size(p),
                                        BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not seek 1\n");
        printf("    part:        %8.8x\n", p->id);
        printf("    part offset: %li\n", bpak_part_offset(h, p));
        printf("    part size:   %li\n", bpak_part_size(p));
        goto err_close_io_out;
    }

    /* Update part header to indicate that the part has been coded */
    if (decode_flag)
    {
        p->flags &= ~BPAK_FLAG_TRANSPORT;
        p->transport_size = 0;
    }
    else
    {
        p->transport_size = bpak_alg_output_size(&ins);
        p->flags |= BPAK_FLAG_TRANSPORT;
    }

    bpak_io_seek(tmp, 0, BPAK_IO_SEEK_SET);
    bpak_io_write(tmp, h, sizeof(*h));

    /* Position output stream at the end of the processed part*/
    rc = bpak_io_seek(tmp, bpak_part_offset(h, p) + bpak_part_size(p),
                    BPAK_IO_SEEK_SET);

    if (rc != BPAK_OK)
    {
        printf("Error: Could not seek\n");
        printf("    offset: %li\n", bpak_part_offset(h, p));
        printf("    size:   %li\n", bpak_part_size(p));
        goto err_close_io_out;
    }

    while(true)
    {
        read_bytes = bpak_io_read(io, state_buffer, size);

        if (read_bytes == 0)
            break;

        written_bytes = bpak_io_write(tmp, state_buffer, read_bytes);

        if (read_bytes != written_bytes)
        {
            rc = -BPAK_FAILED;
            goto err_close_io_out;
        }
    }

    rc = bpak_io_replace_file(io, tmp);

err_close_io_out:
    bpak_io_close(tmp);
    return rc;
}

int action_transport(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool verbose = false;
    uint32_t flags = 0;
    const char *filename = NULL;
    const char *part_ref = NULL;
    const char *origin_file = NULL;
    const char *output_file = NULL;
    const char *encoder_alg = NULL;
    const char *decoder_alg = NULL;
    bool add_flag = false;
    bool encode_flag = false;
    bool decode_flag = false;
    int rc = 0;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"add",         no_argument,       0,  'a' },
        {"origin",      required_argument, 0,  'O' },
        {"output",      required_argument, 0,  'o' },
        {"encoder",     required_argument, 0,  'e' },
        {"decoder",     required_argument, 0,  'd' },
        {"encode",      no_argument,       0,  'E' },
        {"decode",      no_argument,       0,  'D' },
        {"part-ref",    required_argument, 0,  'r' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvao:s:O:e:d:EGr:",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_transport_usage();
                return 0;
            case 'v':
                bpak_inc_verbosity();
            break;
            case 'a':
                add_flag = true;
            break;
            case 'E':
                encode_flag = true;
            break;
            case 'r':
                part_ref = (const char *) optarg;
            break;
            case 'O':
                origin_file = (const char *) optarg;
            break;
            case 'o':
                output_file = (const char *) optarg;
            break;
            case 'e':
                encoder_alg = (const char *) optarg;
            break;
            case 'd':
                decoder_alg = (const char *) optarg;
            break;
            case 'D':
                decode_flag = true;
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

    if ((!decode_flag) && (!add_flag) && (!encode_flag))
    {
        printf("Error: Requried argument either --add, --encode or --decode\n");
        return -1;
    }

    if (encode_flag + add_flag + decode_flag > 1)
    {
        printf("Error: Only one of --add, --encode or --decode is allowed\n");
        return -1;
    }

    struct bpak_io *io = NULL;
    struct bpak_io *origin = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    rc = bpak_io_init_file(&io, filename, "rb+");

    if (rc != BPAK_OK)
    {
        printf("Error: Could not open file\n");
        goto err_free_header_out;
    }

    if (origin_file)
    {
        rc = bpak_io_init_file(&origin, origin_file, "rb+");

        if (rc != BPAK_OK)
        {
            printf("Error: Could not open file\n");
            goto err_free_header_out;
        }
    }

    bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
    size_t read_bytes = bpak_io_read(io, h, sizeof(*h));

    if (bpak_get_verbosity() > 1)
        printf("Read header\n");

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

    if (bpak_get_verbosity() > 1)
        printf("Valid header\n");

    if (encode_flag || decode_flag)
    {
        uint8_t *state_buffer = malloc(1024*1024);
        memset(state_buffer, 0, 1024*1024);

        struct bpak_transport_meta *tm = NULL;

        bpak_foreach_meta(h, mh)
        {
            if (mh->id == id("bpak-transport"))
            {
                bpak_get_meta(h, mh->id, (void **) &tm);

                rc = transport_process(tm, h, mh->part_id_ref,
                        io, origin, state_buffer, 1024*1024, decode_flag);

                if (rc != BPAK_OK)
                    break;

            }
        }

        free(state_buffer);
    }
    else if (add_flag)
    {
        struct bpak_transport_meta *meta = NULL;

        rc = bpak_add_meta(h, id("bpak-transport"), id(part_ref),
                                        (void **) &meta, sizeof(*meta));

        if (rc != BPAK_OK)
            goto err_free_header_out;

        meta->alg_id_encode = id(encoder_alg);
        meta->alg_id_decode = id(decoder_alg);

        bpak_io_seek(io, 0, BPAK_IO_SEEK_SET);
        bpak_io_write(io, h, sizeof(*h));
    }
    else
    {
        printf("Error: Unknown command");
    }

    if (rc != BPAK_OK)
        printf("Error: Transport encoding/decoding failed\n");

err_free_header_out:
    free(h);
err_close_io_out:
    bpak_io_close(io);
    return rc;
}

