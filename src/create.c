#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bpak_tool.h"

int action_create(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool force_overwrite = false;
    const char *filename;
    const char *hash_kind_str = NULL;
    const char *signature_kind_str = NULL;
    uint8_t hash_kind = BPAK_HASH_INVALID;
    uint8_t signature_kind = BPAK_SIGN_INVALID;
    int rc = 0;

    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"force", no_argument, 0, 'Y'},
        {"hash-kind", required_argument, 0, 'H'},
        {"signature-kind", required_argument, 0, 'S'},
        {0, 0, 0, 0}};

    while (
        (opt = getopt_long(argc, argv, "hvYH:S:", long_options, &long_index)) !=
        -1) {
        switch (opt) {
        case 'h':
            print_create_usage();
            return 0;
            break;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'Y':
            force_overwrite = true;
            break;
        case '?':
            printf("Unknown option: %c\n", optopt);
            return -1;
            break;
        case 'H':
            hash_kind_str = (const char *)optarg;
            break;
        case 'S':
            signature_kind_str = (const char *)optarg;
            break;
        case ':':
            printf("Missing arg for %c\n", optopt);
            return -1;
            break;
        default:
            return -1;
        }
    }

    if (optind < argc) {
        filename = (const char *)argv[optind++];
    } else {
        printf("Missing filename argument\n");
        return -1;
    }

    if (!hash_kind_str) {
        if (bpak_get_verbosity())
            printf("Using default hash: SHA256\n");

        hash_kind = BPAK_HASH_SHA256;
    } else if (strcmp(hash_kind_str, "sha256") == 0) {
        hash_kind = BPAK_HASH_SHA256;
    } else if (strcmp(hash_kind_str, "sha384") == 0) {
        hash_kind = BPAK_HASH_SHA384;
    } else if (strcmp(hash_kind_str, "sha512") == 0) {
        hash_kind = BPAK_HASH_SHA512;
    } else {
        printf("Error: '%s' is not a known hash method\n", hash_kind_str);
        return -BPAK_UNSUPPORTED_HASH_ALG;
    }

    if (!signature_kind_str) {
        if (bpak_get_verbosity())
            printf("Using default signature method: prime256v1\n");

        signature_kind = BPAK_SIGN_PRIME256v1;
    } else if (strcmp(signature_kind_str, "prime256v1") == 0) {
        signature_kind = BPAK_SIGN_PRIME256v1;
    } else if (strcmp(signature_kind_str, "secp384r1") == 0) {
        signature_kind = BPAK_SIGN_SECP384r1;
    } else if (strcmp(signature_kind_str, "secp521r1") == 0) {
        signature_kind = BPAK_SIGN_SECP521r1;
    } else if (strcmp(signature_kind_str, "rsa4096") == 0) {
        signature_kind = BPAK_SIGN_RSA4096;
    } else {
        printf("Error: '%s' is not a known signature method\n",
               signature_kind_str);
        return -BPAK_UNSUPPORTED_KEY;
    }

    /* Check if file exists */
    struct stat s;

    if (stat(filename, &s) == 0 && !force_overwrite) {
        printf("Warning: File '%s' already exists, overwrite? Y/N: ", filename);
        fflush(stdout);
        char response = getc(stdin);

        if (response != 'Y') {
            printf("\nAborting\n");
            return -1;
        }
    }

    FILE *fp = NULL;
    struct bpak_header *h = NULL;
    ;

    h = malloc(sizeof(*h));
    if (!h)
        return -BPAK_FAILED;

    memset(h, 0, sizeof(*h));

    rc = bpak_init_header(h);

    if (rc != BPAK_OK)
        goto err_free_header_out;

    h->hash_kind = hash_kind;
    h->signature_kind = signature_kind;

    fp = fopen(filename, "wb");

    if (fp == NULL) {
        rc = -BPAK_FILE_NOT_FOUND;
        goto err_free_header_out;
    }

    size_t written = fwrite(h, 1, sizeof(*h), fp);

    if (written != sizeof(*h)) {
        rc = -BPAK_WRITE_ERROR;
        goto err_close_io_out;
    }

err_close_io_out:
    fclose(fp);
err_free_header_out:
    free(h);
    return rc;
}
