/*
 * Header parsing: a header that passes bpak_valid_header must be safe to use
 * with the meta data and part functions.
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include "fuzz.h"

static void check_meta(struct bpak_header *h, struct bpak_meta_header *m)
{
    struct bpak_meta_header *found = NULL;
    uint8_t value[UINT16_MAX];

    FUZZ_ASSERT(bpak_get_meta(h, m->id, m->part_id_ref, &found) == BPAK_OK);
    FUZZ_ASSERT(found != NULL && found->id == m->id);
    FUZZ_ASSERT(bpak_get_meta_anyref(h, m->id, &found) == BPAK_OK);

    /* The value must be inside the header, h is allocated with its exact
     * size */
    memcpy(value, bpak_get_meta_ptr(h, m, uint8_t), m->size);

    /* The string must be terminated within the buffer, for every buffer
     * size */
    for (size_t size = 1; size <= 256; size *= 2) {
        char *buf = malloc(size);

        FUZZ_ASSERT(buf != NULL);
        memset(buf, 'x', size);

        if (bpak_meta_to_string(h, m, buf, size) == BPAK_OK)
            FUZZ_ASSERT(memchr(buf, 0, size) != NULL);

        free(buf);
    }
}

static void check_part(struct bpak_header *h, struct bpak_part_header *p)
{
    struct bpak_part_header *found = NULL;

    FUZZ_ASSERT(bpak_get_part(h, p->id, &found) == BPAK_OK);
    FUZZ_ASSERT(found != NULL && found->id == p->id);

    (void)bpak_part_offset(h, p);
    (void)bpak_part_size(p);
    (void)bpak_part_size_wo_pad(p);
    (void)bpak_hash_tree_id_to_part_id(h, p->id);
}

/* The tool modifies headers of packages it did not create */
static void check_modify(const struct bpak_header *orig)
{
    struct bpak_header *h = malloc(sizeof(*h));
    struct bpak_meta_header *meta = NULL;
    struct bpak_part_header *part = NULL;

    FUZZ_ASSERT(h != NULL);

    memcpy(h, orig, sizeof(*h));
    if (h->meta[0].id != 0)
        bpak_del_meta(h, &h->meta[0]);
    if (bpak_add_meta(h, 0x12345678, 0, 16, &meta) == BPAK_OK)
        memset(bpak_get_meta_ptr(h, meta, uint8_t), 0xa5, meta->size);

    memcpy(h, orig, sizeof(*h));
    if (h->parts[0].id != 0)
        bpak_del_part(h, &h->parts[0]);
    (void)bpak_add_part(h, 0x12345678, &part);

    free(h);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct bpak_header *h = calloc(1, sizeof(*h));

    FUZZ_ASSERT(h != NULL);
    memcpy(h, data, BPAK_MIN(size, sizeof(*h)));

    if (bpak_valid_header(h) != BPAK_OK)
        goto out;

    bpak_foreach_meta (h, m) {
        if (m->id != 0)
            check_meta(h, m);
    }

    bpak_foreach_part (h, p) {
        if (p->id != 0)
            check_part(h, p);
    }

    check_modify(h);

out:
    free(h);
    return 0;
}
