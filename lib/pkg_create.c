/**
 * BPAK - Bit Packer
 *
 * Copyright (C) 2019 Jonas Blixt <jonpe960@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpak/bpak.h>
#include <bpak/pkg.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include <bpak/merkle.h>
#include <bpak/crc.h>
#include <bpak/crypto.h>

#if BPAK_CONFIG_MERKLE == 1
static ssize_t merkle_wr(off_t offset, uint8_t *buf, size_t size, void *priv)
{
    uint8_t *data = (uint8_t *)priv;
    memcpy(&data[offset], buf, size);
    return size;
}

static ssize_t merkle_rd(off_t offset, uint8_t *buf, size_t size, void *priv)
{
    uint8_t *data = (uint8_t *)priv + offset;
    memcpy(buf, data, size);
    return size;
}

BPAK_EXPORT int bpak_pkg_add_file_with_merkle_tree(struct bpak_package *pkg,
                                                   const char *filename,
                                                   const char *part_name,
                                                   uint8_t flags)
{
    int rc;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_merkle_context ctx;
    struct stat statbuf;
    uint8_t block_buf[BPAK_CHUNK_BUFFER_LENGTH];
    size_t chunk_sz;
    uint64_t new_offset = sizeof(*h);

    if (stat(filename, &statbuf) != 0) {
        bpak_printf(0, "Error: Can't open file '%s'\n", filename);
        return -BPAK_FILE_NOT_FOUND;
    }

    rc = bpak_pkg_add_file(pkg, filename, part_name, flags);

    if (rc != 0)
        return rc;

    ssize_t merkle_sz = bpak_merkle_compute_size(statbuf.st_size);

    if (merkle_sz < 0)
        return merkle_sz;

    char *merkle_buf = bpak_calloc(merkle_sz, 1);

    memset(merkle_buf, 0, merkle_sz);

    bpak_printf(1, "Allocated %li bytes for merkle tree\n", merkle_sz);

    bpak_merkle_hash_t salt;
    memset(salt, 0, 32);

    uint32_t *salt_ptr = (uint32_t *)salt;

    for (unsigned int i = 0; i < sizeof(salt) / sizeof(uint32_t); i++) {
        (*salt_ptr) = random() & 0xFFFFFFFF;
        salt_ptr++;
    }

    rc = bpak_merkle_init(&ctx,
                          statbuf.st_size,
                          salt,
                          32,
                          merkle_wr,
                          merkle_rd,
                          0,
                          true,
                          merkle_buf);

    FILE *fp = fopen(filename, "rb");

    if (fp == NULL) {
        rc = -BPAK_FILE_NOT_FOUND;
        goto err_free_buf_out;
    }

    rc = BPAK_OK;
    while (true) {
        chunk_sz = fread(block_buf, 1, sizeof(block_buf), fp);

        if (chunk_sz == 0)
            break;

        rc = bpak_merkle_write_chunk(&ctx, block_buf, chunk_sz);

        if (rc != BPAK_OK)
            goto err_close_fp_out;
    }

    bpak_merkle_hash_t hash;

    rc = bpak_merkle_finish(&ctx, hash);

    if (rc != BPAK_OK)
        goto err_close_fp_out;

    /* Write tree to bpak file */

    bpak_foreach_part (h, p) {
        new_offset += (p->size + p->pad_bytes);
    }

    /* Add salt */
    uint8_t *m = NULL;

    rc = bpak_add_meta(h,
                       BPAK_ID_MERKLE_SALT,
                       bpak_id(part_name),
                       (void **)&m,
                       sizeof(bpak_merkle_hash_t));

    if (rc != BPAK_OK)
        goto err_close_fp_out;

    memcpy(m, salt, sizeof(bpak_merkle_hash_t));

    m = NULL;
    rc = bpak_add_meta(h,
                       BPAK_ID_MERKLE_ROOT_HASH,
                       bpak_id(part_name),
                       (void **)&m,
                       sizeof(bpak_merkle_hash_t));

    if (rc != BPAK_OK)
        goto err_close_fp_out;

    memcpy(m, hash, sizeof(bpak_merkle_hash_t));

    struct bpak_part_header *p = NULL;
    uint32_t hash_tree_id =
        bpak_crc32(0, (uint8_t *)part_name, strlen(part_name));
    hash_tree_id = bpak_crc32(hash_tree_id, (uint8_t *)"-hash-tree", 10);
    rc = bpak_add_part(h, hash_tree_id, &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not add part\n");
        goto err_close_fp_out;
    }

    p->offset = new_offset;
    p->flags = flags;
    p->size = merkle_sz;
    p->pad_bytes =
        0; /* Merkle tree is multiples of 4kByte, no padding needed */

    rc = fseek(pkg->fp, new_offset, SEEK_SET);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Could not seek to new pos\n");
        goto err_close_fp_out;
    }

    if (fwrite(merkle_buf, 1, merkle_sz, pkg->fp) != (size_t)merkle_sz) {
        rc = -BPAK_WRITE_ERROR;
        goto err_close_fp_out;
    }

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not update payload hash\n");
        goto err_close_fp_out;
    }

    rc = bpak_pkg_write_header(pkg);
err_close_fp_out:
    fclose(fp);
err_free_buf_out:
    bpak_free(merkle_buf);
    return rc;
}

#endif // BPAK_CONFIG_MERKLE

BPAK_EXPORT int bpak_pkg_add_file(struct bpak_package *pkg,
                                  const char *filename, const char *part_name,
                                  uint8_t flags)
{
    int rc;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *p = NULL;
    struct stat statbuf;
    uint64_t new_offset = sizeof(struct bpak_header);
    char chunk_buffer[BPAK_CHUNK_BUFFER_LENGTH];

    if (stat(filename, &statbuf) != 0) {
        bpak_printf(0, "Error: can't open file '%s'\n", filename);
        return -BPAK_FILE_NOT_FOUND;
    }

    FILE *in_fp = NULL;

    bpak_printf(1, "Adding %s <%s>\n", part_name, filename);

    bpak_foreach_part (h, p) {
        new_offset += (p->size + p->pad_bytes);
    }

    rc = bpak_add_part(h, bpak_id(part_name), &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not add part\n");
        return rc;
    }

    p->id = bpak_id(part_name);
    p->offset = new_offset;
    p->flags = flags;
    p->size = statbuf.st_size;

    if (statbuf.st_size % BPAK_PART_ALIGN)
        p->pad_bytes = BPAK_PART_ALIGN - (statbuf.st_size % BPAK_PART_ALIGN);
    else
        p->pad_bytes = 0;

    rc = fseek(pkg->fp, new_offset, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "Error: Could not seek to new pos\n");
        return -BPAK_SEEK_ERROR;
    }

    uint64_t bytes_to_write = p->size;

    in_fp = fopen(filename, "r");

    if (!in_fp) {
        bpak_printf(0, "Could not open input file: %s\n", filename);
        return -BPAK_FILE_NOT_FOUND;
    }

    while (bytes_to_write) {
        size_t read_bytes = fread(chunk_buffer, 1, sizeof(chunk_buffer), in_fp);
        if (fwrite(chunk_buffer, 1, read_bytes, pkg->fp) != read_bytes) {
            rc = -BPAK_WRITE_ERROR;
            break;
        }
        bytes_to_write -= read_bytes;
    }

    if (rc != BPAK_OK) {
        goto err_close_fp;
    }

    if (p->pad_bytes) {
        bpak_printf(2, "Adding %i z-pad\n", p->pad_bytes);
        memset(chunk_buffer, 0, sizeof(chunk_buffer));
        if (fwrite(chunk_buffer, 1, p->pad_bytes, pkg->fp) != p->pad_bytes) {
            rc = -BPAK_WRITE_ERROR;
            goto err_close_fp;
        }
    }

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not update payload hash\n");
        goto err_close_fp;
    }

    rc = bpak_pkg_write_header(pkg);

err_close_fp:
    fclose(in_fp);
    return rc;
}

BPAK_EXPORT int bpak_pkg_add_key(struct bpak_package *pkg, const char *filename,
                                 const char *part_name, uint8_t flags)
{
    int rc;
    struct bpak_key *key = NULL;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *p = NULL;
    uint64_t new_offset = sizeof(struct bpak_header);

    rc = bpak_crypto_load_public_key(filename, &key);

    if (rc != BPAK_OK)
        return rc;

    /* Write header */
    bpak_foreach_part (h, p) {
        new_offset += (p->size + p->pad_bytes);
    }

    rc = bpak_add_part(h, bpak_id(part_name), &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not add part\n");
        goto err_free_key_out;
    }

    p->id = bpak_id(part_name);
    p->offset = new_offset;
    p->flags = flags;
    p->size = key->size;

    if (key->size % BPAK_PART_ALIGN)
        p->pad_bytes = BPAK_PART_ALIGN - (key->size % BPAK_PART_ALIGN);
    else
        p->pad_bytes = 0;

    rc = fseek(pkg->fp, new_offset, SEEK_SET);

    if (rc != 0) {
        bpak_printf(0, "Could not seek to new pos\n");
        rc = -BPAK_SEEK_ERROR;
        goto err_free_key_out;
    }

    /* Write key data */
    if (fwrite(key->data, 1, key->size, pkg->fp) != key->size) {
        rc = -BPAK_WRITE_ERROR;
        goto err_free_key_out;
    }

    /* Write zero padding */
    uint8_t zero = 0;
    if (fwrite(&zero, 1, p->pad_bytes, pkg->fp) != p->pad_bytes) {
        rc = -BPAK_WRITE_ERROR;
        goto err_free_key_out;
    }

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not update payload hash\n");
        goto err_free_key_out;
    }

    rc = bpak_pkg_write_header(pkg);

    if (rc != BPAK_OK)
        goto err_free_key_out;

err_free_key_out:
    free(key);
    return rc;
}
