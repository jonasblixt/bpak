#include <stdio.h>
#include <bpak/bpak.h>

int main(int argc, char **argv)
{
    const char *filename = "a-1.0.0.bpak";
    FILE *fp = NULL;
    struct bpak_header header;
    int rc = 0;

    printf("Reading '%s'...\n", filename);
    fp = fopen(filename, "r");

    if (!fp)
    {
        printf("Error: Could not open '%s'\n", filename);
        return -1;
    }

    if (fread(&header, sizeof(header), 1, fp) != 1)
    {
        printf("Error: Could not read header\n");
        rc = -1;
        goto err_out_close;
    }

    rc = bpak_valid_header(&header);

    if (rc != BPAK_OK)
    {
        printf("Error: Invalid header\n");
        goto err_out_close;
    }

    bpak_foreach_meta(&header, m)
    {
        if (!m->id)
            break;
        printf("Found metadata %x, size: %i bytes, offset: %i\n",
                    m->id, m->size, m->offset);
    }

err_out_close:
    fclose(fp);
    return rc;
}
