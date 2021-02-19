/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */


#include <stdio.h>
#include <stdalign.h>
#include <string.h>
#include <bpak/crc.h>
#include "bpak_tool.h"

static int verbosity;

void bpak_inc_verbosity(void)
{
    verbosity++;
}

int bpak_get_verbosity(void)
{
    return verbosity;
}

void print_version(void)
{
    printf("BitPacker %s\n", PACKAGE_VERSION);
}

void print_common_usage(void)
{
    printf("Common options:\n");
    printf("    -v, --verbose                   Verbose output\n");
    printf("\n");

    printf("Help options:\n");
    printf("    -h, --help                      Show this help message\n");
    printf("    -V, --version                   Display version\n");
    printf("\n");
}

void print_set_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak set <filename.bpak>\n");
    printf("\n");

    printf("Set options:\n");
    printf("    -m, --meta                      Update meta data\n");
    printf("    -s, --from-string               String input\n");
    printf("    -e, --encoder\n");

    printf("\nKey hint configuration:\n");
    printf("    -k, --key-id <id>               Set key id\n");
    printf("    -i, --keystore-id <id>          Key from key-store with id <id>\n");
    printf("\n");

    print_common_usage();
}

void print_extract_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak extract <filename.bpak>        Extract parts from bpak file\n");
    printf("\n");

    printf("Extract options:\n");
    printf("    -m, --meta <id>                 Extract meta data\n");
    printf("    -p, --part <id>                 Extract part\n");
    printf("    -o, --output <filename>\n");
    printf("    -r, --part-ref=ref              Reference part\n");
    printf("\n");

    print_common_usage();
}

void print_create_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak create <filename.bpak>         Create an empty bpak file\n");
    printf("\n");

    printf("Create options:\n");
    printf("    -Y, --force                     Overwrite existing file without asking\n");
    printf("    -H, --hash-kind                 Hash kind (SHA-256 default)\n");
    printf("    -S, --signature-kind            Signature kind (prime256v1 default)\n");
    printf("\n");

    print_common_usage();
}


void print_compare_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak compare <first.bpak> <second.bpak>        Compare files\n");
    printf("\n");

    print_common_usage();
}

void print_transport_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak transport <filename.bpak> (--add || --encode || --decode) [options]    Transport operations\n");
    printf("\n");

    printf("Transport commands:\n");
    printf("    -a, --add                 Add transport meta data\n");
    printf("    -E, --encode              Encode archive for transport\n");
    printf("    -D, --decode              Decode package\n");
    printf("\n");

    printf("Add options:\n");
    printf("    -p, --part                Which part id to operate on\n");
    printf("    -e, --encode              Encoder algorithm to use\n");
    printf("    -d, --decode              Decoder algorithm to use\n");
    printf("\n");

    printf("Encode/Decode options:\n");
    printf("    -O, --origin              Source data to use during encoding/decoding\n");
    printf("    -R, --rate-limit <n>      Rate-limit operation 0-100\n");
    printf("    -o, --output <fn>         Write to output to <fn>\n");
    printf("Decode options:\n");
    printf("    -H, --output-header-last  Write output header at the end\n");
    printf("\n");

    print_common_usage();
}
void print_show_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak show <filename.bpak> [options]  Show information on a bpak file\n");
    printf("\n");

    printf("Options:\n");
    printf("    -m, --meta <id>                 Show information about meta with id\n");
    printf("    -p, --part <id>                 Show information about part with id\n");
    printf("    -H, --hash                      Print package hash\n");
    printf("    -B, --binary-hash               Output package hash in binary form\n");
    printf("\n");

    print_common_usage();
}

void print_generate_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak generate <generator> <options> <filename.bpak>\n");
    printf("\n");

    printf("Generators:\n");
    printf("    keystore                        Generate keystore code\n");
    printf("    id                              Translate strings to id's\n");
    printf("\n");

    printf("Keystore options:\n");
    printf("    -n, --name                      Output name\n");
    printf("\n");

    print_common_usage();
}

void print_add_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak add <filename.bpak> <options>  Add data to a file\n");
    printf("\n");

    printf("Add options:\n");
    printf("    -p, --part=id                   Add part with id 'id'\n");
    printf("    -m, --meta=id                   Add metadata with id 'id'\n");
    printf("    -f, --from-file=filename        Load file\n");
    printf("    -s, --from-string=string        Load from string\n");
    printf("    -e, --encoder=encoder           Use 'encoder' to code data\n");
    printf("    -F, --set-flag=flag             Set flag 'flag' for this part\n");
    printf("    -r, --part-ref=ref              Reference part\n");
    printf("\n");

    printf("Optional flags:\n");
    printf("    dont-hash                       Exclude part from hashing context\n");
    printf("\n");

    printf("Encoders that can be used together with --from-string:\n");
    printf("    integer                         Encode as integer\n");
    printf("    uuid                            Encode as UUID\n");
    printf("\n");

    printf("Encoders that can be used together with --from-file:\n");
    printf("    key                             Encode as DER key\n");
    printf("    merkle                          Encode as merkle tree\n");
    printf("\n");

    print_common_usage();
}

void print_sign_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak sign <filename.bpak> <options>  Sign a bpak file\n");
    printf("\n");

    printf("Sign options:\n");
    printf("    -f, --signature <filename>       Write precomputed signature\n");
    printf("    -k, --key <key>                  Sign using key <key>\n");
}

void print_verify_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak verify <filename.bpak> <options>  Verify a bpak file\n");
    printf("\n");

    printf("Verify options:\n");
    printf("    -k, --key <key>                  Verify using key <key>\n");
}

void print_usage(void)
{
    print_version();
    printf("\n");
    printf("bpak <action> <filename> ...\n");
    printf("\n");

    printf("Actions:\n");

    printf("    create                          Create empty bpak file\n");
    printf("    add                             Add part to file\n");
    printf("    transport                       Transport operations\n");
    printf("    sign                            Sign\n");
    printf("    verify                          Verify signature\n");
    printf("    show                            Show information about file\n");
    printf("    set                             Update metadata\n");
    printf("    generate                        Various generators\n");
    printf("    compare                         Compare bpak files\n");
    printf("    extract                         Extract parts or meta data\n");
    printf("\n");

    print_common_usage();

/*
    printf("Built-in algorithms:\n");

    uint8_t *p = (uint8_t *) bpak_alg_tbl_start();
    uint8_t *e = (uint8_t *) bpak_alg_tbl_end();

    while (p < e)
    {
        struct bpak_alg *alg = (struct bpak_alg *) p;
        printf("    %s [%8.8x]\n", alg->name, alg->id);

        p += sizeof(struct bpak_alg) + (32 - sizeof(struct bpak_alg) % 32);
    }
*/
}
