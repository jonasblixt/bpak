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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpak/id.h>

#include "bpak_tool.h"

int action_set(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *filename = NULL;
    const char *meta_name = NULL;
    const char *from_string = NULL;
    const char *encoder = NULL;
    uint32_t key_id = 0;
    uint32_t keystore_id = 0;
    bool key_id_flag = false;
    bool keystore_id_flag = false;
    int rc = 0;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "meta", required_argument, 0, 'm' },
        { "from-string", required_argument, 0, 's' },
        { "encoder", required_argument, 0, 'e' },
        { "key-id", required_argument, 0, 'k' },
        { "keystore-id", required_argument, 0, 'i' },
        { 0, 0, 0, 0 },
    };

    while ((opt = getopt_long(argc,
                              argv,
                              "hvp:m:s:e:k:i:",
                              long_options,
                              &long_index)) != -1) {
        switch (opt) {
        case 'h':
            print_set_usage();
            return 0;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'k':
            key_id_flag = true;
            key_id = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'i':
            keystore_id_flag = true;
            keystore_id = bpak_get_id_for_name_or_ref(optarg);
            break;
        case 'm':
            meta_name = (const char *)optarg;
            break;
        case 's':
            from_string = (const char *)optarg;
            break;
        case 'e':
            encoder = (const char *)optarg;
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

    if (!meta_name && !(key_id_flag || keystore_id_flag)) {
        fprintf(
            stderr,
            "Error: Requried argument --meta (or keystore-id and key-id) is "
            "missing\n");
        return -1;
    }

    if (!from_string && meta_name) {
        fprintf(stderr, "Error: Missing required option --from_string <...>\n");
        return -1;
    }

    FILE *fp = NULL;
    struct bpak_header *h = malloc(sizeof(struct bpak_header));

    fp = fopen(filename, "r+");

    if (fp == NULL) {
        rc = -BPAK_FILE_NOT_FOUND;
        goto err_free_header_out;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_close_fp_out;
    }

    size_t read_bytes = fread(h, 1, sizeof(*h), fp);

    if (read_bytes != sizeof(*h)) {
        rc = -BPAK_READ_ERROR;
        fprintf(stderr, "Error: Could not read header %li\n", read_bytes);
        goto err_close_fp_out;
    }

    rc = bpak_valid_header(h);

    if (rc != BPAK_OK) {
        fprintf(stderr, "Error: Invalid header. Not a BPAK file?\n");
        goto err_close_fp_out;
    }

    if (meta_name) {
        struct bpak_meta_header *meta = NULL;

        rc = bpak_get_meta(h,
                           bpak_id(meta_name),
                           0,
                           &meta);

        if (rc != BPAK_OK || meta == NULL) {
            fprintf(stderr, "Error: Could not find '%s'\n", meta_name);
            goto err_close_fp_out;
        }

        if (!encoder) {
            size_t len = strlen(from_string);

            if (len + 1 > meta->size) {
                if (bpak_get_verbosity() > 2) {
                   printf("Need to grow metadata field. Remove and re-add");
                }

                struct bpak_header *tmp_header = malloc(sizeof(struct bpak_header));
                memcpy(tmp_header, h, sizeof(struct bpak_header));

                struct bpak_meta_header *meta_tmp = NULL;

                rc = bpak_get_meta(tmp_header, meta->id, meta->part_id_ref, &meta_tmp);
                if (rc != BPAK_OK) {
                    /* There is no error case where this should happen except for
                     * internal bugs
                     */
                    fprintf(stderr, "FATAL ERROR");
                    goto err_close_fp_out;
                }

                bpak_del_meta(tmp_header, meta_tmp);

                rc = bpak_add_meta(tmp_header,
                                   meta->id,
                                   meta->part_id_ref,
                                   len + 1,
                                   &meta_tmp);
                if (rc != BPAK_OK) {
                    fprintf(stderr, "Failed to allocate space for updated meta %s\n",
                            meta_name);
                    free(tmp_header);
                    goto err_close_fp_out;
                }

                meta = meta_tmp;
                free(h);
                h = tmp_header;
            }

            uint8_t *meta_data = bpak_get_meta_ptr(h, meta, uint8_t);

            memcpy(meta_data, from_string, len + 1);
            memset(meta_data + len + 1, 0, meta->size - len - 1);

        } else if (strcmp(encoder, "integer") == 0) {
            if (meta->size != sizeof(uint64_t)) {
                fprintf(stderr, "Incorrect meta data length\n");
                rc = -BPAK_SIZE_ERROR;
                goto err_close_fp_out;
            }

            char *endptr = NULL;

            errno = 0;
            uint64_t value = strtol(from_string, &endptr, 0);

            if (endptr == from_string ||
                errno != 0) {
                rc = -BPAK_FAILED;
                fprintf(stderr, "Error: Could not parse input as a number");
                goto err_close_fp_out;
            }

            *bpak_get_meta_ptr(h, meta, uint64_t) = value;
        } else if (strcmp(encoder, "id") == 0) {
            if (meta->size != sizeof(bpak_id_t)) {
                fprintf(stderr, "Incorrect meta data length\n");
                rc = -BPAK_SIZE_ERROR;
                goto err_close_fp_out;
            }

            *bpak_get_meta_ptr(h, meta, bpak_id_t) = bpak_id(from_string);
        } else {
            rc = -BPAK_FAILED;
            fprintf(stderr, "Error: Unknown encoder\n");
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
    } else {
        rc = -BPAK_FAILED;
        fprintf(stderr, "Error: Don't know what to do\n");
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        rc = -BPAK_SEEK_ERROR;
        goto err_close_fp_out;
    }

    if (fwrite(h, 1, sizeof(*h), fp) != sizeof(*h)) {
        rc = -BPAK_WRITE_ERROR;
        goto err_close_fp_out;
    }

err_close_fp_out:
    fclose(fp);
err_free_header_out:
    free(h);
    return rc;
}
