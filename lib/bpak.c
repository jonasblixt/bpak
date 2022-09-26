/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2022 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include <bpak/bpak.h>
#include <bpak/id.h>

BPAK_EXPORT int bpak_get_meta_and_header(struct bpak_header *hdr, uint32_t id,
        uint32_t part_id_ref, void **output, void *offset,
        struct bpak_meta_header **header)
{
    bpak_foreach_meta(hdr, m) {
        if (m->id == id) {
            if (part_id_ref != 0) {
                if (m->part_id_ref != part_id_ref)
                    continue;
            }

            void *tmp = (void *) &hdr->metadata[m->offset];

            if (offset) {
                if (tmp <= offset)
                    continue;
            }

            (*output) = tmp;

            if (header)
                (*header) = m;

            return BPAK_OK;
        }
    }

    (*output) = NULL;
    return -BPAK_NOT_FOUND;
}

BPAK_EXPORT int bpak_get_meta(struct bpak_header *hdr, uint32_t id, void **output,
                    void *offset)
{
    return bpak_get_meta_and_header(hdr, id, 0, output, offset,
                    (struct bpak_meta_header  **) 0);
}

BPAK_EXPORT int bpak_get_meta_with_ref(struct bpak_header *hdr, uint32_t id,
                            uint32_t part_id_ref, void **output, void *offset)
{
    return bpak_get_meta_and_header(hdr, id, part_id_ref, output, offset,
                    (struct bpak_meta_header  **) 0);
}

BPAK_EXPORT int bpak_add_meta(struct bpak_header *hdr, uint32_t id, uint32_t part_ref_id,
                    void **ptr, uint16_t size)
{
    uint16_t new_offset = 0;

    bpak_foreach_meta(hdr, m) {
        if (!m->id) {
            m->id = id;
            m->offset = new_offset;
            m->size = size;
            m->part_id_ref = part_ref_id;
            if ((m->offset + m->size) > BPAK_METADATA_BYTES)
                return -BPAK_NO_SPACE_LEFT;

            (*ptr) = (void *) &hdr->metadata[m->offset];
            return BPAK_OK;
        }

        new_offset += m->size;

        if (m->size % BPAK_META_ALIGN)
            new_offset += BPAK_META_ALIGN - (m->size % BPAK_META_ALIGN);
    }

    return -BPAK_NO_SPACE_LEFT;
}

BPAK_EXPORT int bpak_get_part(struct bpak_header *hdr, uint32_t id,
                  struct bpak_part_header **part)
{
    void *offset = *part;

    bpak_foreach_part(hdr, p) {
        if (p->id == id) {
            if (offset) {
                if (((void *) p) <= offset)
                    continue;
            }

            (*part) = p;
            return BPAK_OK;
        }
    }

    return -BPAK_NOT_FOUND;
}

BPAK_EXPORT int bpak_add_part(struct bpak_header *hdr, uint32_t id,
                  struct bpak_part_header **part)
{
    bpak_foreach_part(hdr, p) {
        if(!p->id) {
            p->id = id;
            (*part) = p;
            return BPAK_OK;
        }
    }

    return -BPAK_NO_SPACE_LEFT;
}

BPAK_EXPORT int bpak_init_header(struct bpak_header *hdr)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = BPAK_HEADER_MAGIC;
    hdr->hash_kind = BPAK_HASH_SHA256;
    hdr->signature_kind = BPAK_SIGN_PRIME256v1;
    hdr->alignment = BPAK_PART_ALIGN;
    return BPAK_OK;
}

BPAK_EXPORT const char *bpak_error_string(int code)
{
    switch (code) {
        case BPAK_OK:
            return "OK";
        case -BPAK_FAILED:
            return "Failed";
        case -BPAK_NOT_FOUND:
            return "Not found";
        case -BPAK_SIZE_ERROR:
            return "Size error";
        case -BPAK_NO_SPACE_LEFT:
            return "No space left";
        case -BPAK_BAD_ALIGNMENT:
            return "Bad alignment";
        case -BPAK_SEEK_ERROR:
            return "Seek error";
        case -BPAK_NOT_SUPPORTED:
            return "Not supported";
        case -BPAK_NEEDS_MORE_DATA:
            return "Needs more data";
        case -BPAK_WRITE_ERROR:
            return "Write error";
        case -BPAK_DECOMPRESSOR_ERROR:
            return "Decompressor error";
        case -BPAK_COMPRESSOR_ERROR:
            return "Compressor error";
        case -BPAK_PATCH_READ_ORIGIN_ERROR:
            return "Patch read origin error";
        case -BPAK_PATCH_WRITE_ERROR:
            return "Patch write error";
        case -BPAK_READ_ERROR:
            return "Read error";
        case -BPAK_BAD_MAGIC:
            return "Bad magic";
        case -BPAK_UNSUPPORTED_HASH_ALG:
            return "Unsupported hash algorithm";
        case -BPAK_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case -BPAK_FILE_NOT_FOUND:
            return "File not found";
        case -BPAK_KEY_DECODE:
            return "Could not decode key";
        case -BPAK_VERIFY_FAIL:
            return "Verification failed";
        case -BPAK_SIGN_FAIL:
            return "Signing failed";
        case -BPAK_UNSUPPORTED_KEY:
            return "Unsupported key";
        case -BPAK_BAD_ROOT_HASH:
            return "Bad root hash";
        case -BPAK_BAD_PAYLOAD_HASH:
            return "Bad payload hash";
        case -BPAK_MISSING_META_DATA:
            return "Missing meta data";
        case -BPAK_PACKAGE_UUID_MISMATCH:
            return "Package UUID mismatch";
        case -BPAK_UNSUPPORTED_COMPRESSION:
            return "Unsupported compression method";
        case -BPAK_KEY_NOT_FOUND:
            return "Key not found";
        default:
            return "Unknown";
    }
}

BPAK_EXPORT int bpak_valid_header(struct bpak_header *hdr)
{
    if (hdr->magic != BPAK_HEADER_MAGIC)
        return -BPAK_BAD_MAGIC;

    /* Check alignment of part data blocks */
    bpak_foreach_part(hdr, p) {
        if (!p->id)
            break;

        if (((p->size + p->pad_bytes) % BPAK_PART_ALIGN) != 0)
            return -BPAK_BAD_ALIGNMENT;
    }

    /* Check for out-of-bounds metadata */
    bpak_foreach_meta(hdr, m) {
        if (!m->id)
            break;

        if ((m->size + m->offset) > BPAK_METADATA_BYTES)
        {
            return -BPAK_SIZE_ERROR;
        }
    }

    if (!hdr->hash_kind)
        return -BPAK_NOT_SUPPORTED;

    return BPAK_OK;
}

BPAK_EXPORT off_t bpak_part_offset(struct bpak_header *h, struct bpak_part_header *part)
{
    off_t offset = sizeof(*h);

    bpak_foreach_part(h, p) {
        if (!p->id)
            break;
        if (p->id == part->id)
            break;

        offset += bpak_part_size(p);
    }

    return offset;
}

BPAK_EXPORT size_t bpak_part_size(struct bpak_part_header *part)
{
    if (part->flags & BPAK_FLAG_TRANSPORT)
        return part->transport_size;
    else
        return (part->size + part->pad_bytes);
}

BPAK_EXPORT size_t bpak_part_size_wo_pad(struct bpak_part_header *part)
{
    if (part->flags & BPAK_FLAG_TRANSPORT)
        return part->transport_size;
    else
        return (part->size);
}

BPAK_EXPORT const char *bpak_signature_kind(uint8_t signature_kind)
{
    switch(signature_kind) {
        case BPAK_SIGN_PRIME256v1:
            return "prime256v1";
        case BPAK_SIGN_SECP384r1:
            return "secp384r1";
        case BPAK_SIGN_SECP521r1:
            return "secp521r1";
        case BPAK_SIGN_RSA4096:
            return "rsa4096";
        default:
            return "Unknown";
    }
}

BPAK_EXPORT const char *bpak_hash_kind(uint8_t hash_kind)
{
    switch(hash_kind) {
        case BPAK_HASH_SHA256:
            return "sha256";
        case BPAK_HASH_SHA384:
            return "sha384";
        case BPAK_HASH_SHA512:
            return "sha512";
        default:
            return "Unknown";
    }
}

BPAK_EXPORT __attribute__ ((weak)) int bpak_printf(int verbosity, const char *fmt, ...)
{
    (void) verbosity;
    (void) fmt;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_copyz_signature(struct bpak_header *header, uint8_t *signature,
                         size_t *size)
{
    if (header->signature_sz > BPAK_SIGNATURE_MAX_BYTES)
        return -BPAK_SIZE_ERROR;
    if (header->signature_sz == 0)
        return -BPAK_SIZE_ERROR;
    if (header->signature_sz > *size)
        return -BPAK_SIZE_ERROR;

    (*size) = header->signature_sz;
    memcpy(signature, header->signature, header->signature_sz);
    memset(header->signature, 0, sizeof(header->signature));
    header->signature_sz = 0;

    return BPAK_OK;
}

BPAK_EXPORT int bpak_set_key_id(struct bpak_header *hdr, uint32_t key_id)
{
    hdr->key_id = key_id;
    return BPAK_OK;
}

BPAK_EXPORT int bpak_set_keystore_id(struct bpak_header *hdr, uint32_t keystore_id)
{
    hdr->keystore_id = keystore_id;
    return BPAK_OK;
}

BPAK_EXPORT int bpak_add_transport_meta(struct bpak_header *header, uint32_t part_id,
                                uint32_t encoder_id, uint32_t decoder_id)
{
    int rc;
    struct bpak_transport_meta *meta = NULL;

                            /* id("bpak-transport") = 0x2d44bbfb */
    rc = bpak_add_meta(header, 0x2d44bbfb, part_id, (void **) &meta,
                            sizeof(*meta));

    if (rc != BPAK_OK)
        return rc;

    meta->alg_id_encode = encoder_id;
    meta->alg_id_decode = decoder_id;

    return BPAK_OK;
}

BPAK_EXPORT const char *bpak_version(void)
{
    return BPAK_VERSION_STRING;
}
