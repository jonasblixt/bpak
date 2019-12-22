#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/crc.h>

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

uint32_t bpak_uuid_to_string(uint8_t *uuid_in, char *out, size_t size)
{
    uint8_t uuid[16];

    memcpy(uuid, uuid_in, 16);

    uint32_t *u0 = (uint32_t *) &uuid[0];
    uint16_t *u1 = (uint16_t *) &uuid[4];
    uint16_t *u2 = (uint16_t *) &uuid[6];
    uint16_t *u3 = (uint16_t *) &uuid[8];
    uint16_t *u4 = (uint16_t *) &uuid[10];
    uint32_t *u5 = (uint32_t *) &uuid[12];

    *u0 = ((*u0 >> 24) & 0xff) |
          ((*u0 << 8)  & 0xff0000) |
          ((*u0 >> 8)  & 0xff00) |
          ((*u0 << 24) & 0xff000000);


    *u1 = (*u1 >> 8) | (*u1 << 8);
    *u2 = (*u2 >> 8) | (*u2 << 8);
    *u3 = (*u3 >> 8) | (*u3 << 8);
    *u4 = (*u4 >> 8) | (*u4 << 8);

    *u5 = ((*u5 >> 24) & 0xff) |
          ((*u5 << 8)  & 0xff0000) |
          ((*u5 >> 8)  & 0xff00) |
          ((*u5 << 24) & 0xff000000);

    snprintf(out, size, "%08x-%04x-%04x-%04x-%04x%08x",
                *u0, *u1, *u2, *u3, *u4, *u5);

    return BPAK_OK;
}

int bpak_meta_to_string(struct bpak_header *h, struct bpak_meta_header *m,
                        char *buf, size_t size)
{
    uint32_t *id_ptr;
    uint8_t *byte_ptr;

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
        bpak_get_meta(h, m->id, (void **) &id_ptr);
        bpak_uuid_to_string((uint8_t *) id_ptr, buf, size);
    }
    else if (m->id == bpak_id("bpak-package-uid"))
    {
        bpak_get_meta(h, m->id, (void **) &id_ptr);

        bpak_uuid_to_string((uint8_t *) id_ptr, buf, size);
    }
    else if (m->id == bpak_id("bpak-transport"))
    {
        struct bpak_transport_meta *transport_meta =
            (struct bpak_transport_meta *) &(h->metadata[m->offset]);
        //bpak_get_meta(h, m->id, (void **) &transport_meta);

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
    else
    {
        if (size)
            *buf = 0;
    }

    return BPAK_OK;
}
