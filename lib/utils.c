#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/crc.h>
#include <bpak/pkg.h>

#include "uuid/uuid.h"

uint32_t bpak_id(const char *str)
{
    return bpak_crc32(0, (const uint8_t *) str, strlen(str));
}

int bpak_bin2hex(uint8_t *data, size_t data_sz, char *buf, size_t buf_sz)
{
    uint8_t b;
    int i = data_sz;
    int n = 0;

    for (i = 0; i < data_sz; i++)
    {
        b = data[i];
        b = (b >> 4) & 0x0F;
        buf[n++] = (b > 9)?('a' + (b-10)):('0' + b);

        b = data[i];
        b = b & 0x0F;
        buf[n++] = (b > 9)?('a' + (b-10)):('0' + b);
    }

    buf[n] = 0;

    return BPAK_OK;
}

int bpak_uuid_to_string(const uint8_t *data, char *buf, size_t size)
{
    if (size < 37)
        return -BPAK_FAILED;

    uuid_unparse(data, buf);

    return BPAK_OK;
}

int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size)
{
    uint32_t *id_ptr = NULL;
    uint8_t *byte_ptr = NULL;

    if (m->id == bpak_id("bpak-key-id"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr);
        snprintf(buf, size, "%x", *id_ptr);
    }
    else if (m->id == bpak_id("bpak-key-store"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr);
        snprintf(buf, size, "%x", *id_ptr);
    }
    else if (m->id == bpak_id("bpak-package"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr);
        bpak_uuid_to_string(byte_ptr, buf, size);

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
        bpak_get_meta(h, m->id, (void **) &byte_ptr);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    }
    else if(m->id == bpak_id("merkle-root-hash"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr);
        bpak_bin2hex(byte_ptr, 32, buf, size);
    }
    else if(m->id == bpak_id("pb-load-addr"))
    {
        uint64_t *entry_addr = (uint64_t *) &(h->metadata[m->offset]);
        snprintf(buf, size, "Entry: %p", (void *) *entry_addr);
    }
    else if (m->id == bpak_id("bpak-version"))
    {
        bpak_get_meta(h, m->id, (void **) &byte_ptr);

        if (m->size > size)
            return -BPAK_FAILED;

        memcpy(buf, byte_ptr, m->size);
    }
    else if (m->id == bpak_id("bpak-dependency"))
    {

        uint8_t uuid_str[64];

        struct bpak_dependency *d = \
                   (struct bpak_dependency *) &(h->metadata[m->offset]);


        bpak_uuid_to_string(d->uuid, uuid_str, sizeof(uuid_str));

        snprintf(buf, size, "%s (%s)", uuid_str, d->constraint);

    }
    else if (m->id == bpak_id("bpak-key-mask"))
    {
        uint64_t *key_mask = (uint64_t *) &(h->metadata[m->offset]);
        snprintf(buf, size, "mask: 0x%8.8x", (uint32_t) *key_mask);
    }
    else
    {
        if (size)
            *buf = 0;
    }

    return BPAK_OK;
}
