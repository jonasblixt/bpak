#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#include "bpak_tool.h"

int bpak_printf(int verbosity, const char *fmt, ...)
{
    if (bpak_get_verbosity() < verbosity)
        return BPAK_OK;

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return BPAK_OK;
}

int main(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    const char *action = NULL;
    const char *filename = NULL;

    struct option long_options[] =
    {
        {"help",      no_argument,       0,  'h' },
        {"version",   no_argument,       0,  'V' },
        {0,           0,                 0,   0  }
    };

    if (argc < 2)
    {
        print_usage();
        return 0;
    }

    srand(time(NULL));

    if (bpak_pkg_register_all_algs() != BPAK_OK)
    {
        printf("Error: could not initialize all algorithms\n");
        return -1;
    }

    while ((opt = getopt_long(2, argv, "hV",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_usage();
                return 0;
            break;
            case 'V':
                print_version();
                return 0;
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
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc)
    {
        action = (const char *) argv[optind++];
        optind = 1;
        argv++;
        argc--;

        /* Check for valid action */
        if (strcmp(action, "create") == 0)
        {
            return action_create(argc, argv);
        }
        else if (strcmp(action, "add") == 0)
        {
            return action_add(argc, argv);
        }
        else if (strcmp(action, "show") == 0)
        {
            return action_show(argc, argv);
        }
        else if (strcmp(action, "sign") == 0)
        {
            return action_sign(argc, argv);
        }
        else if (strcmp(action, "verify") == 0)
        {
            return action_verify(argc, argv);
        }
        else if (strcmp(action, "generate") == 0)
        {
            return action_generate(argc, argv);
        }
        else if (strcmp(action, "transport") == 0)
        {
            return action_transport(argc, argv);
        }
        else if (strcmp(action, "set") == 0)
        {
            return action_set(argc, argv);
        }
        else if (strcmp(action, "compare") == 0)
        {
            return action_compare(argc, argv);
        }
        else if (strcmp(action, "extract") == 0)
        {
            return action_extract(argc, argv);
        }
        else
        {
            printf ("Unknown action '%s'\n", action);
            return -1;
        }
    }
    else
    {
        printf("Unknown action and/or filename\n");
        return -1;
    }

    return 0;
}
