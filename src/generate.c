#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpak/bpak.h>
#include <bpak/id.h>
#include <bpak/crypto.h>

#include "uuid.h"
#include "bpak_tool.h"

int action_generate(int argc, char **argv)
{
    int opt;
    int rc = 0;
    int long_index = 0;
    const char *filename = NULL;
    const char *generator = NULL;
    const char *keystore_name = NULL;
    bool decorate_keystore = false;
    struct bpak_key *key = NULL;

    struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "name", required_argument, 0, 'n' },
        { "decorate", no_argument, 0, 'd' },
        { 0, 0, 0, 0 },
    };

    while (
        (opt = getopt_long(argc, argv, "hvdn:", long_options, &long_index)) !=
        -1) {
        switch (opt) {
        case 'h':
            print_generate_usage();
            return 0;
            break;
        case 'v':
            bpak_inc_verbosity();
            break;
        case 'n':
            keystore_name = optarg;
            break;
        case 'd':
            decorate_keystore = true;
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
        generator = (const char *)argv[optind++];
    } else {
        fprintf(stderr, "Missing generator argument\n");
        return -1;
    }

    if (strcmp(generator, "id") == 0) {
        char *id_string = NULL;

        if (optind < argc) {
            id_string = argv[optind++];
        } else {
            fprintf(stderr, "Missing id-string argument\n");
            return -1;
        }

        printf("id(\"%s\") = 0x%8.8x\n", id_string, bpak_id(id_string));
        rc = BPAK_OK;
    } else if (strcmp(generator, "keystore") == 0) {
        if (optind < argc) {
            filename = (const char *)argv[optind++];
        } else {
            fprintf(stderr, "Missing filename argument\n");
            return -1;
        }

        if (keystore_name == NULL) {
            fprintf(stderr, "Error: Missing --name parameter\n");
            return -BPAK_FAILED;
        }

        FILE *fp = NULL;
        struct bpak_header *h = malloc(sizeof(struct bpak_header));

        if (!h)
            return -BPAK_FAILED;

        fp = fopen(filename, "rb");

        if (fp == NULL) {
            rc = -BPAK_NOT_FOUND;
            goto err_free_header_out;
        }

        size_t read_bytes = fread(h, 1, sizeof(*h), fp);

        if (read_bytes != sizeof(*h)) {
            rc = -BPAK_READ_ERROR;
            goto err_free_io_out;
        }

        unsigned char *package_id = NULL;

        rc = bpak_get_meta(h,
                           bpak_id("bpak-package"),
                           (void **)&package_id,
                           NULL);

        if (rc != BPAK_OK) {
            fprintf(stderr, "Error: Could not read bpak-package-id\n");
            goto err_free_io_out;
        }

        uint32_t *keystore_provider_id = NULL;

        rc = bpak_get_meta(h,
                           bpak_id("keystore-provider-id"),
                           (void **)&keystore_provider_id,
                           NULL);

        if (rc != BPAK_OK) {
            fprintf(stderr,
                    "Error: Could not read keystore-provider-id meta\n");
            goto err_free_io_out;
        }

        int key_index = 0;
        unsigned char key_buffer[4096];

        printf("/* Automatically generated with bpak %s */\n",
               BPAK_VERSION_STRING);
        printf("#include <bpak/bpak.h>\n");
        printf("#include <bpak/keystore.h>\n");

        printf("\n\n");

        char *keystore_name_copy = strdup(keystore_name);

        for (unsigned int i = 0; i < strlen(keystore_name); i++) {
            if (keystore_name[i] == '-')
                keystore_name_copy[i] = '_';
        }

        bpak_foreach_part (h, p) {
            if (!p->id)
                continue;

            const char *keystore_key_decorator =
                "__attribute__((section (\".keystore_key\"))) ";

            printf("const struct bpak_key keystore_%s_key%i %s=\n",
                   keystore_name_copy,
                   key_index,
                   decorate_keystore ? keystore_key_decorator : "");

            printf("{\n");
            printf("    .id = 0x%x,\n", p->id);
            printf("    .size = %li,\n", p->size);

            if (fseek(fp, p->offset, SEEK_SET) != 0) {
                rc = -BPAK_SEEK_ERROR;
                goto err_free_keystore_name;
            }

            read_bytes = fread(key_buffer, 1, p->size, fp);

            if (read_bytes != p->size) {
                rc = -BPAK_READ_ERROR;
                fprintf(stderr, "Error: Could not read key\n");
                goto err_free_keystore_name;
            }

            rc = bpak_crypto_parse_public_key(key_buffer, p->size, &key);

            if (rc != BPAK_OK) {
                fprintf(stderr,
                        "Error: Could not parse key (part: 0x%x)\n",
                        p->id);
                goto err_free_keystore_name;
            }

            switch (key->kind) {
            case BPAK_KEY_PUB_PRIME256v1:
                printf("    .kind = BPAK_KEY_PUB_PRIME256v1,\n");
                break;
            case BPAK_KEY_PUB_SECP384r1:
                printf("    .kind = BPAK_KEY_PUB_SECP384r1,\n");
                break;
            case BPAK_KEY_PUB_SECP521r1:
                printf("    .kind = BPAK_KEY_PUB_SECP521r1,\n");
                break;
            case BPAK_KEY_PUB_RSA4096:
                printf("    .kind = BPAK_KEY_PUB_RSA4096,\n");
                break;
            default:
                fprintf(stderr, "Key-type (%i)\n", key->kind);
                rc = -BPAK_UNSUPPORTED_KEY;
                goto err_free_key_out;
            }
            printf("    .data =\n");
            printf("    {\n");
            printf("            ");
            for (unsigned int i = 0; i < key->size; i++) {
                printf("0x%2.2x, ", key->data[i] & 0xFF);
                if ((i + 1) % 8 == 0)
                    printf("\n            ");
            }
            printf("\n    },\n");

            printf("};\n\n");
            key_index++;
            free(key);
            key = NULL;
        }

        const char *keystore_header_decorator =
            "__attribute__((section (\".keystore_header\"))) ";

        printf("const struct bpak_keystore keystore_%s %s=\n",
               keystore_name_copy,
               decorate_keystore ? keystore_header_decorator : "");
        printf("{\n");
        printf("    .id = 0x%x,\n", *keystore_provider_id);
        printf("    .no_of_keys = %i,\n", key_index);
        printf("    .verified = true,\n");
        printf("    .keys =\n");
        printf("    {\n");
        for (int i = 0; i < key_index; i++)
            printf("        (struct bpak_key *) &keystore_%s_key%i,\n",
                   keystore_name_copy,
                   i);
        printf("    },\n");
        printf("};\n");
err_free_key_out:
        if (key != NULL)
            free(key);
err_free_keystore_name:
        free(keystore_name_copy);
err_free_io_out:
        fclose(fp);
err_free_header_out:
        free(h);
    }

    return rc;
}
