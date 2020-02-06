#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uuid.h>

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "bpak_tool.h"

int action_generate(int argc, char **argv)
{
    int opt;
    int rc = 0;
    int long_index = 0;
    const char *filename = NULL;
    const char *generator = NULL;
    const char *keystore_name = NULL;

    struct option long_options[] =
    {
        {"help",      no_argument,       0,  'h' },
        {"verbose",   no_argument,       0,  'v' },
        {"name",      required_argument, 0,  'n' },
        {0,           0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hv",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
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
        generator = (const char *) argv[optind++];
    }
    else
    {
        printf("Missing generator argument\n");
        return -1;
    }

    if (strcmp(generator, "id") == 0)
    {
        char *id_string = NULL;

        if (optind < argc)
        {
            id_string =  argv[optind++];
        }
        else
        {
            printf("Missing id-string argument\n");
            return -1;
        }

        printf("id(\"%s\") = 0x%8.8x\n", id_string, id(id_string));
        rc = BPAK_OK;
    }
    else if (strcmp(generator, "keystore") == 0)
    {
        if (optind < argc)
        {
            filename = (const char *) argv[optind++];
        }
        else
        {
            printf("Missing filename argument\n");
            return -1;
        }

        if(keystore_name == NULL)
        {
            printf("Error: Missing --name parameter\n");
            return -BPAK_FAILED;
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

        char *package_id = NULL;

        rc = bpak_get_meta(h, id("bpak-package"), (void **) &package_id);

        if (rc != BPAK_OK)
        {
            printf("Error: Could not read bpak-package-id\n");
            goto err_free_io_out;
        }

        uuid_t keystore_uuid;

        uuid_parse(BPAK_KEYSTORE_UUID, keystore_uuid);

        if (uuid_compare(keystore_uuid, package_id) != 0)
        {
            printf("Error: This is not a keystore file\n");
            rc = -BPAK_FAILED;
            goto err_free_io_out;
        }

        mbedtls_pk_context ctx;

        int key_index = 0;
        char key_buffer[4096];
        mbedtls_pk_init(&ctx);

        printf("/* Automatically generated with %s %s */\n", PACKAGE_NAME,
                                                             PACKAGE_VERSION);
        printf("#include <bpak/bpak.h>\n");
        printf("#include <bpak/keystore.h>\n");

        printf("\n\n");

        char *keystore_name_copy = strdup(keystore_name);

        for (int i = 0; i < strlen(keystore_name); i++)
        {
            if (keystore_name[i] == '-')
                keystore_name_copy[i] = '_';
        }

        bpak_foreach_part(h, p)
        {
            if (!p->id)
                continue;

            printf("const struct bpak_key keystore_%s_key%i =\n",
                                                    keystore_name_copy,
                                                    key_index);

            uint32_t *key_mask = NULL;

            rc = bpak_get_meta_with_ref(h, bpak_id("bpak-key-mask"),
                                           p->id, (void **) &key_mask);

            printf("{\n");
            printf("    .id = 0x%x,\n", p->id);
            printf("    .size = %li,\n", p->size);
            if (rc == BPAK_OK)
                printf("    .key_mask = 0x%x,\n", *key_mask);
            else
                printf("    .key_mask = 0x00,\n");

            bpak_io_seek(io, p->offset, BPAK_IO_SEEK_SET);
            read_bytes = bpak_io_read(io, key_buffer, p->size);

            if (read_bytes != p->size)
            {
                rc = -BPAK_FAILED;
                printf("Error: Could not read key\n");
                goto err_free_header_out;
            }

            mbedtls_pk_free(&ctx);
            rc = mbedtls_pk_parse_public_key(&ctx, key_buffer, p->size);

            if (rc != 0)
            {
                printf("Error: Coult not parse key\n");
                rc = -BPAK_FAILED;
                goto err_free_ctx;
            }

            if (strcmp(mbedtls_pk_get_name(&ctx), "EC") == 0)
            {
                switch (mbedtls_pk_get_bitlen(&ctx))
                {
                    case 256:
                        printf("    .kind = BPAK_KEY_PUB_PRIME256v1,\n");
                    break;
                    case 384:
                        printf("    .kind = BPAK_KEY_PUB_SECP384r1,\n");
                    break;
                    case 521:
                        printf("    .kind = BPAK_KEY_PUB_SECP521r1,\n");
                    break;
                    default:
                        printf("Unknown bit-length (%li)\n",
                                mbedtls_pk_get_bitlen(&ctx));
                        rc = -BPAK_FAILED;
                        goto err_free_ctx;
                };
            }
            else if(strcmp(mbedtls_pk_get_name(&ctx), "RSA") == 0)
            {
                if (mbedtls_pk_get_bitlen(&ctx) == 4096)
                {
                    printf("    .kind = BPAK_KEY_PUB_RSA4096,\n");
                }
                else
                {
                    printf("Unknown bit-length (%li)\n",
                            mbedtls_pk_get_bitlen(&ctx));
                    rc = -BPAK_FAILED;
                    goto err_free_ctx;
                }
            }
            else
            {
                printf("Error: Unknown key type (%s)\n", mbedtls_pk_get_name(&ctx));
                rc = -BPAK_FAILED;
                goto err_free_ctx;
            }
            printf("    .data =\n");
            printf("    {\n");
            printf("            ");
            for (int i = 0; i < p->size; i++)
            {
                printf("0x%2.2x, ", key_buffer[i] & 0xFF);
                if ((i+1) % 8 == 0)
                    printf("\n            ");
            }
            printf("\n    },\n");

            printf("};\n\n");
            key_index++;
        }


        printf("const struct bpak_keystore keystore_%s =\n",
                                                    keystore_name_copy);
        printf("{\n");
        printf("    .id = 0x%x,\n", id(keystore_name));
        printf("    .no_of_keys = %i,\n", key_index);
        printf("    .verified = true,\n");
        printf("    .keys =\n");
        printf("    {\n");
        for (int i = 0; i < key_index; i++)
            printf("        (struct bpak_key *) &keystore_%s_key%i,\n",
                                                keystore_name_copy, i);
        printf("    },\n");
        printf("};\n");
    err_free_ctx:
        mbedtls_pk_free(&ctx);
    err_free_header_out:
        free(h);
    err_free_io_out:
        bpak_io_close(io);

    }

    return rc;
}
