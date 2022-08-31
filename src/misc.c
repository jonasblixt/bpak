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
#include <bpak/id.h>
#include "bpak_tool.h"
#include <uuid.h>

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
    printf("    -d, --decorate                  Decorate structs with section attribute\n");
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
    printf("    id                              Encode as bpak id\n");
    printf("    dependency                      Encode as UUID-semver tuple\n");
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
}

int uuid_to_string(const uint8_t *data, char *buf, size_t size)
{
    if (size < 37)
        return -BPAK_FAILED;

    uuid_unparse(data, buf);

    return BPAK_OK;
}

int meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size)
{
    uint32_t *id_ptr = NULL;
    uint8_t *byte_ptr = NULL;

    if (m->id == bpak_id("bpak-key-id"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr, NULL);
        snprintf(buf, size, "%x", *id_ptr);
    }
    else if (m->id == bpak_id("bpak-key-store"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr, NULL);
        snprintf(buf, size, "%x", *id_ptr);
    }
    else if (m->id == bpak_id("bpak-package"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr, NULL);
        uuid_to_string(byte_ptr, buf, size);

    }
    else if (m->id == bpak_id("bpak-transport"))
    {
        struct bpak_transport_meta *transport_meta =
            (struct bpak_transport_meta *) &(h->metadata[m->offset]);

        snprintf(buf, size, "Encode: %8.8x, Decode: %8.8x",
                        transport_meta->alg_id_encode,
                        transport_meta->alg_id_decode);
    }
    else if(m->id == bpak_id("merkle-salt"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr, NULL);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    }
    else if(m->id == bpak_id("merkle-root-hash"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr, NULL);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    }
    else if(m->id == bpak_id("pb-load-addr"))
    {
        uint64_t *entry_addr = (uint64_t *) &(h->metadata[m->offset]);
        snprintf(buf, size, "Entry: %p", (void *) *entry_addr);
    }
    else if (m->id == bpak_id("bpak-version"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr, NULL);

        if (m->size > size)
            return -BPAK_FAILED;

        memcpy(buf, byte_ptr, m->size);
    }
    else if (m->id == bpak_id("bpak-dependency"))
    {

        uint8_t uuid_str[64];

        struct bpak_dependency *d = \
                   (struct bpak_dependency *) &(h->metadata[m->offset]);


        uuid_to_string(d->uuid, uuid_str, sizeof(uuid_str));

        snprintf(buf, size, "%s (%s)", uuid_str, d->constraint);

    }
    else if (m->id == bpak_id("keystore-provider-id"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr, NULL);
        snprintf(buf, size, "0x%x", *id_ptr);
    }
    else
    {
        if (size)
            *buf = 0;
    }

    return BPAK_OK;
}
