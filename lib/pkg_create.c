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
#include <stdlib.h>
#include <sys/random.h>
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

#include "internal.h"

static const uint8_t zeros[BPAK_PART_ALIGN];

/* The package before it is changed, to restore it when the change fails */
struct pkg_state {
    struct bpak_header header;
    off_t file_size;
};

static int pkg_save(struct bpak_package *pkg, struct pkg_state *state)
{
    struct stat statbuf;

    if (fflush(pkg->fp) != 0)
        return -BPAK_WRITE_ERROR;

    if (fstat(fileno(pkg->fp), &statbuf) != 0)
        return -BPAK_READ_ERROR;

    memcpy(&state->header, &pkg->header, sizeof(state->header));
    state->file_size = statbuf.st_size;
    return BPAK_OK;
}

/* Restore the header in memory and in the file, and remove appended data */
static void pkg_restore(struct bpak_package *pkg, struct pkg_state *state)
{
    memcpy(&pkg->header, &state->header, sizeof(pkg->header));

    if (bpak_pkg_write_header(pkg) != BPAK_OK || fflush(pkg->fp) != 0 ||
        ftruncate(fileno(pkg->fp), state->file_size) != 0) {
        bpak_printf(0, "Error: Could not restore the package\n");
    }
}

/* Add the part 'id' of 'size' bytes after the other parts and seek to where
 * its data is stored. Transport encoded parts are stored with their transport
 * size, the offset of the part is its offset in the decoded package. */
static int pkg_add_part_start(struct bpak_package *pkg, bpak_id_t id,
                              uint8_t flags, uint64_t size,
                              struct bpak_part_header **part)
{
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *p = NULL;
    uint64_t stored_end = sizeof(*h);
    uint64_t decoded_end = sizeof(*h);
    int rc;

    bpak_foreach_part (h, other) {
        if (!other->id)
            break;

        stored_end += bpak_part_size(other);
        decoded_end += other->size + other->pad_bytes;
    }

    rc = bpak_add_part(h, id, &p);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not add part\n");
        return rc;
    }

    p->offset = decoded_end;
    p->flags = flags;
    p->size = size;

    if (size % BPAK_PART_ALIGN)
        p->pad_bytes = BPAK_PART_ALIGN - (size % BPAK_PART_ALIGN);
    else
        p->pad_bytes = 0;

    if (fseeko(pkg->fp, (off_t)stored_end, SEEK_SET) != 0) {
        bpak_printf(0, "Error: Could not seek to new pos\n");
        return -BPAK_SEEK_ERROR;
    }

    *part = p;
    return BPAK_OK;
}

/* Write the padding of the part after its data and the header */
static int pkg_add_part_finish(struct bpak_package *pkg,
                               struct bpak_part_header *p)
{
    int rc;

    if (fwrite(zeros, 1, p->pad_bytes, pkg->fp) != p->pad_bytes)
        return -BPAK_WRITE_ERROR;

    rc = bpak_pkg_update_hash(pkg, NULL, NULL);

    if (rc != BPAK_OK) {
        bpak_printf(0, "Error: Could not update payload hash\n");
        return rc;
    }

    return bpak_pkg_write_header(pkg);
}

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

static int merkle_write_chunk(void *priv, uint8_t *buffer, size_t length)
{
    return bpak_merkle_write_chunk(priv, buffer, length);
}

/* Compute the hash tree of the data of part 'p' in the package */
static int compute_merkle_tree(struct bpak_package *pkg,
                               struct bpak_part_header *p, uint8_t *tree,
                               const bpak_merkle_hash_t salt,
                               bpak_merkle_hash_t root_hash)
{
    struct bpak_merkle_context ctx;
    int rc;

    rc = bpak_merkle_init(&ctx,
                          p->size,
                          salt,
                          sizeof(bpak_merkle_hash_t),
                          merkle_wr,
                          merkle_rd,
                          0,
                          true,
                          tree);

    if (rc != BPAK_OK)
        return rc;

    if (fseeko(pkg->fp, bpak_part_offset(&pkg->header, p), SEEK_SET) != 0)
        return -BPAK_SEEK_ERROR;

    rc = bpak_file_feed(pkg->fp, p->size, merkle_write_chunk, &ctx);

    if (rc != BPAK_OK)
        return rc;

    return bpak_merkle_finish(&ctx, root_hash);
}

BPAK_EXPORT int bpak_pkg_add_file_with_merkle_tree(struct bpak_package *pkg,
                                                   const char *filename,
                                                   const char *part_name,
                                                   uint8_t flags)
{
    int rc;
    struct bpak_header *h = bpak_pkg_header(pkg);
    struct bpak_part_header *p = NULL;
    struct bpak_part_header *tree_part = NULL;
    struct bpak_meta_header *meta = NULL;
    struct pkg_state saved;
    uint8_t *tree = NULL;
    bpak_merkle_hash_t salt;
    bpak_merkle_hash_t root_hash;
    ssize_t tree_size;

    rc = pkg_save(pkg, &saved);

    if (rc != BPAK_OK)
        return rc;

    /* bpak_pkg_add_file restores the package when it fails */
    rc = bpak_pkg_add_file(pkg, filename, part_name, flags);

    if (rc != BPAK_OK)
        return rc;

    rc = bpak_get_part(h, bpak_id(part_name), &p);

    if (rc != BPAK_OK)
        goto err_restore_out;

    tree_size = bpak_merkle_compute_size(p->size);

    if (tree_size < 0) {
        rc = tree_size;
        goto err_restore_out;
    }

    tree = bpak_calloc(tree_size, 1);

    if (tree == NULL) {
        rc = -BPAK_FAILED;
        goto err_restore_out;
    }

    bpak_printf(1, "Allocated %zd bytes for merkle tree\n", tree_size);

    if (getentropy(salt, sizeof(salt)) != 0) {
        bpak_printf(0, "Error: Could not create a random salt\n");
        rc = -BPAK_FAILED;
        goto err_free_tree_out;
    }

    /* From the data in the package, the file may have changed since it was
     * added */
    rc = compute_merkle_tree(pkg, p, tree, salt, root_hash);

    if (rc != BPAK_OK)
        goto err_free_tree_out;

    rc = bpak_add_meta(h, BPAK_ID_MERKLE_SALT, p->id, sizeof(salt), &meta);

    if (rc != BPAK_OK)
        goto err_free_tree_out;

    memcpy(bpak_get_meta_ptr(h, meta, uint8_t), salt, sizeof(salt));

    rc = bpak_add_meta(h,
                       BPAK_ID_MERKLE_ROOT_HASH,
                       p->id,
                       sizeof(root_hash),
                       &meta);

    if (rc != BPAK_OK)
        goto err_free_tree_out;

    memcpy(bpak_get_meta_ptr(h, meta, uint8_t), root_hash, sizeof(root_hash));

    /* The tree is a multiple of 4 KiB, it has no padding */
    rc = pkg_add_part_start(pkg,
                            bpak_part_id_to_hash_tree_id(p->id),
                            flags,
                            tree_size,
                            &tree_part);

    if (rc == BPAK_OK &&
        fwrite(tree, 1, tree_size, pkg->fp) != (size_t)tree_size)
        rc = -BPAK_WRITE_ERROR;

    if (rc == BPAK_OK)
        rc = pkg_add_part_finish(pkg, tree_part);

err_free_tree_out:
    bpak_free(tree);
err_restore_out:
    if (rc != BPAK_OK)
        pkg_restore(pkg, &saved);
    return rc;
}

#endif // BPAK_CONFIG_MERKLE

BPAK_EXPORT int bpak_pkg_add_file(struct bpak_package *pkg,
                                  const char *filename, const char *part_name,
                                  uint8_t flags)
{
    int rc;
    struct bpak_part_header *p = NULL;
    struct pkg_state saved;
    struct stat statbuf;
    FILE *in_fp = NULL;

    bpak_printf(1, "Adding %s <%s>\n", part_name, filename);

    in_fp = fopen(filename, "rb");

    if (in_fp == NULL) {
        bpak_printf(0, "Error: can't open file '%s'\n", filename);
        return -BPAK_FILE_NOT_FOUND;
    }

    /* The size of the part is the size of the file when it is opened, a file
     * that becomes shorter is a read error */
    if (fstat(fileno(in_fp), &statbuf) != 0) {
        rc = -BPAK_READ_ERROR;
        goto err_close_fp;
    }

    rc = pkg_save(pkg, &saved);

    if (rc != BPAK_OK)
        goto err_close_fp;

    rc =
        pkg_add_part_start(pkg, bpak_id(part_name), flags, statbuf.st_size, &p);

    if (rc == BPAK_OK)
        rc = bpak_file_copy(in_fp, pkg->fp, p->size);

    if (rc == BPAK_OK)
        rc = pkg_add_part_finish(pkg, p);

    if (rc != BPAK_OK)
        pkg_restore(pkg, &saved);

err_close_fp:
    fclose(in_fp);
    return rc;
}

BPAK_EXPORT int bpak_pkg_add_key(struct bpak_package *pkg, const char *filename,
                                 const char *part_name, uint8_t flags)
{
    int rc;
    struct bpak_key *key = NULL;
    struct bpak_part_header *p = NULL;
    struct pkg_state saved;

    rc = bpak_crypto_load_public_key(filename, &key);

    if (rc != BPAK_OK)
        return rc;

    rc = pkg_save(pkg, &saved);

    if (rc != BPAK_OK)
        goto err_free_key_out;

    rc = pkg_add_part_start(pkg, bpak_id(part_name), flags, key->size, &p);

    if (rc == BPAK_OK && fwrite(key->data, 1, key->size, pkg->fp) != key->size)
        rc = -BPAK_WRITE_ERROR;

    if (rc == BPAK_OK)
        rc = pkg_add_part_finish(pkg, p);

    if (rc != BPAK_OK)
        pkg_restore(pkg, &saved);

err_free_key_out:
    bpak_free(key);
    return rc;
}
