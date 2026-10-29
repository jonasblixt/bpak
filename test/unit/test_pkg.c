#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpak/id.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include <bpak/pkg.h>
#include "test_helpers.h"

static void test_signature_too_large(void **state)
{
    (void)state;
    struct bpak_package pkg;
    uint8_t signature[BPAK_SIGNATURE_MAX_BYTES + 1] = { 0 };
    int rc;

    memset(&pkg, 0, sizeof(pkg));

    /* Rejected before the header is changed or written */
    rc = bpak_pkg_write_raw_signature(&pkg, signature, sizeof(signature));
    assert_int_equal(rc, -BPAK_SIZE_ERROR);
    assert_int_equal(pkg.header.signature_sz, 0);
}

static void test_verify_signature_size(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_key *key = NULL;
    int rc;

    rc = bpak_crypto_load_public_key(TEST_DATA("secp256r1-pub-key.der"), &key);
    assert_int_equal(rc, BPAK_OK);

    memset(&pkg, 0, sizeof(pkg));
    bpak_init_header(&pkg.header);

    /* A DER signature whose lengths reach past the signature field */
    static const uint8_t der[] = { 0x30, 0x82, 0xff, 0xfb,
                                   0x02, 0x82, 0xff, 0xf4 };
    memcpy(pkg.header.signature, der, sizeof(der));
    pkg.header.signature_sz = 0xffff;

    rc = bpak_pkg_verify(&pkg, key);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    pkg.header.signature_sz = sizeof(pkg.header.signature) + 1;
    rc = bpak_pkg_verify(&pkg, key);
    assert_int_equal(rc, -BPAK_SIZE_ERROR);

    free(key);
}

static unsigned int tagged_allocations;

/* An allocator that tags its allocations, freeing anything else fails */
static void *tagged_calloc(size_t nmemb, size_t size)
{
    uint32_t *p = calloc(1, nmemb * size + 16);

    assert_non_null(p);
    *p = 0x62706b61u;
    tagged_allocations++;
    return (uint8_t *)p + 16;
}

static void tagged_free(void *ptr)
{
    if (ptr == NULL)
        return;

    uint32_t *p = (uint32_t *)((uint8_t *)ptr - 16);

    assert_int_equal(*p, 0x62706b61u);
    tagged_allocations--;
    *p = 0;
    free(p);
}

/* Create an empty package in a temporary file */
static void create_package(struct bpak_package *pkg, char *path)
{
    int fd = mkstemp(path);
    int rc;

    assert_true(fd >= 0);
    close(fd);

    rc = bpak_pkg_open(pkg, path, "r+b");
    assert_int_equal(rc, BPAK_OK);
    assert_ptr_equal(pkg->filename, path);
}

static void test_add_key_allocator(void **state)
{
    (void)state;
    struct bpak_package pkg;
    char path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package(&pkg, path);

    tagged_allocations = 0;
    assert_int_equal(bpak_set_calloc_free(tagged_calloc, tagged_free), BPAK_OK);

    rc = bpak_pkg_add_key(&pkg, TEST_DATA("secp256r1-pub-key.der"), "key", 0);

    assert_int_equal(bpak_set_calloc_free(calloc, free), BPAK_OK);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(tagged_allocations, 0);

    bpak_pkg_close(&pkg);
    unlink(path);
}

static off_t file_size(const char *path)
{
    struct stat statbuf;

    assert_int_equal(stat(path, &statbuf), 0);
    return statbuf.st_size;
}

/* Write 'size' bytes to a temporary file */
static void create_file(char *path, size_t size)
{
    int fd = mkstemp(path);

    assert_true(fd >= 0);
    for (size_t i = 0; i < size; i++)
        assert_int_equal(write(fd, "x", 1), 1);
    close(fd);
}

/* A failed add leaves the package as it was, in memory and in the file */
static void test_add_file_failure(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_header before;
    char path[] = "/tmp/bpak-test-XXXXXX";
    char data_path[] = "/tmp/bpak-test-XXXXXX";
    char dir_path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package(&pkg, path);
    create_file(data_path, 1000);
    assert_non_null(mkdtemp(dir_path));

    rc = bpak_pkg_add_file(&pkg, data_path, "a", 0);
    assert_int_equal(rc, BPAK_OK);
    memcpy(&before, &pkg.header, sizeof(before));
    off_t size_before = file_size(path);

    /* fread fails, it returned 0 and the copy looped forever */
    rc = bpak_pkg_add_file(&pkg, dir_path, "b", 0);
    assert_int_equal(rc, -BPAK_READ_ERROR);
    assert_memory_equal(&pkg.header, &before, sizeof(before));

    rc = bpak_pkg_add_file(&pkg, "/nonexistent", "b", 0);
    assert_int_equal(rc, -BPAK_FILE_NOT_FOUND);

    /* The merkle tree needs a multiple of 4 KiB, the data part was left in
     * the package */
    rc = bpak_pkg_add_file_with_merkle_tree(&pkg, data_path, "fs", 0);
    assert_int_equal(rc, -BPAK_BAD_ALIGNMENT);
    assert_memory_equal(&pkg.header, &before, sizeof(before));
    assert_int_equal(file_size(path), size_before);

    bpak_pkg_close(&pkg);

    /* And in the file */
    rc = bpak_pkg_open(&pkg, path, "rb");
    assert_int_equal(rc, BPAK_OK);
    assert_memory_equal(&pkg.header, &before, sizeof(before));
    bpak_pkg_close(&pkg);

    unlink(path);
    unlink(data_path);
    rmdir(dir_path);
}

/* Parts added after a transport encoded part are stored after its transport
 * size, their offset is the offset in the decoded package */
static void test_add_file_after_transport_part(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_part_header *a;
    struct bpak_part_header *b;
    char path[] = "/tmp/bpak-test-XXXXXX";
    char data_path[] = "/tmp/bpak-test-XXXXXX";
    uint8_t data[1000];
    int rc;

    create_package(&pkg, path);
    create_file(data_path, sizeof(data));

    rc = bpak_pkg_add_file(&pkg, data_path, "a", 0);
    assert_int_equal(rc, BPAK_OK);

    /* Part 'a' as transport encoded to 100 bytes */
    rc = bpak_get_part(&pkg.header, bpak_id("a"), &a);
    assert_int_equal(rc, BPAK_OK);
    a->flags |= BPAK_FLAG_TRANSPORT;
    a->transport_size = 100;
    rc = ftruncate(fileno(pkg.fp), sizeof(struct bpak_header) + 100);
    assert_int_equal(rc, 0);

    rc = bpak_pkg_add_file(&pkg, data_path, "b", 0);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_get_part(&pkg.header, bpak_id("b"), &b);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(b->offset, sizeof(struct bpak_header) + 1024);
    assert_int_equal(bpak_part_offset(&pkg.header, b),
                     sizeof(struct bpak_header) + 100);
    assert_int_equal(file_size(path), sizeof(struct bpak_header) + 100 + 1024);

    assert_int_equal(fseeko(pkg.fp, bpak_part_offset(&pkg.header, b), SEEK_SET),
                     0);
    assert_int_equal(fread(data, 1, sizeof(data), pkg.fp), sizeof(data));
    for (size_t i = 0; i < sizeof(data); i++)
        assert_int_equal(data[i], 'x');

    bpak_pkg_close(&pkg);
    unlink(path);
    unlink(data_path);
}

/* A package with parts 'a' and 'b' of 1000 bytes and meta data of 'b' */
static void create_package_ab(struct bpak_package *pkg, char *path,
                              char *data_path)
{
    struct bpak_meta_header *meta;
    int rc;

    create_package(pkg, path);
    create_file(data_path, 1000);

    rc = bpak_pkg_add_file(pkg, data_path, "a", 0);
    assert_int_equal(rc, BPAK_OK);
    rc = bpak_pkg_add_file(pkg, data_path, "b", 0);
    assert_int_equal(rc, BPAK_OK);

    for (unsigned int i = 0; i < 3; i++) {
        rc = bpak_add_meta(&pkg->header, i + 1, bpak_id("b"), 8, &meta);
        assert_int_equal(rc, BPAK_OK);
    }

    rc = bpak_add_meta(&pkg->header, 4, 0, 8, &meta);
    assert_int_equal(rc, BPAK_OK);
}

static void test_delete_part(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_part_header *a;
    struct bpak_meta_header *meta;
    char path[] = "/tmp/bpak-test-XXXXXX";
    char data_path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package_ab(&pkg, path, data_path);

    /* Trailing data after the last part looped forever */
    assert_int_equal(fseeko(pkg.fp, 0, SEEK_END), 0);
    assert_int_equal(fwrite("trailing", 1, 8, pkg.fp), 8);

    rc = bpak_pkg_delete_part(&pkg, bpak_id("a"), true);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(file_size(path), sizeof(struct bpak_header) + 1024);

    rc = bpak_get_part(&pkg.header, bpak_id("a"), &a);
    assert_int_equal(rc, -BPAK_NOT_FOUND);

    /* All meta data of the part */
    rc = bpak_pkg_delete_part(&pkg, bpak_id("b"), true);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(file_size(path), sizeof(struct bpak_header));
    assert_int_equal(pkg.header.meta[0].id, 4);
    assert_int_equal(pkg.header.meta[1].id, 0);
    rc = bpak_get_meta_anyref(&pkg.header, 1, &meta);
    assert_int_equal(rc, -BPAK_NOT_FOUND);

    bpak_pkg_close(&pkg);
    unlink(path);
    unlink(data_path);
}

static void test_delete_part_truncated(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_header before;
    char path[] = "/tmp/bpak-test-XXXXXX";
    char data_path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package_ab(&pkg, path, data_path);
    memcpy(&before, &pkg.header, sizeof(before));

    /* The file ends in part 'b', the copy looped forever */
    rc = ftruncate(fileno(pkg.fp), sizeof(struct bpak_header) + 1500);
    assert_int_equal(rc, 0);

    rc = bpak_pkg_delete_part(&pkg, bpak_id("a"), true);
    assert_int_equal(rc, -BPAK_READ_ERROR);
    assert_memory_equal(&pkg.header, &before, sizeof(before));

    bpak_pkg_close(&pkg);
    unlink(path);
    unlink(data_path);
}

/* The offsets of the following parts move by the decoded size of a
 * transport encoded part, the data by its transport size */
static void test_delete_transport_part(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_part_header *a;
    struct bpak_part_header *b;
    char path[] = "/tmp/bpak-test-XXXXXX";
    char data_path[] = "/tmp/bpak-test-XXXXXX";
    uint8_t data[1000];
    int rc;

    create_package(&pkg, path);
    create_file(data_path, sizeof(data));

    rc = bpak_pkg_add_file(&pkg, data_path, "a", 0);
    assert_int_equal(rc, BPAK_OK);
    rc = bpak_get_part(&pkg.header, bpak_id("a"), &a);
    assert_int_equal(rc, BPAK_OK);
    a->flags |= BPAK_FLAG_TRANSPORT;
    a->transport_size = 100;
    rc = ftruncate(fileno(pkg.fp), sizeof(struct bpak_header) + 100);
    assert_int_equal(rc, 0);
    rc = bpak_pkg_add_file(&pkg, data_path, "b", 0);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_pkg_delete_part(&pkg, bpak_id("a"), true);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_get_part(&pkg.header, bpak_id("b"), &b);
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(b->offset, sizeof(struct bpak_header));
    assert_int_equal(file_size(path), sizeof(struct bpak_header) + 1024);

    assert_int_equal(fseeko(pkg.fp, sizeof(struct bpak_header), SEEK_SET), 0);
    assert_int_equal(fread(data, 1, sizeof(data), pkg.fp), sizeof(data));
    for (size_t i = 0; i < sizeof(data); i++)
        assert_int_equal(data[i], 'x');

    bpak_pkg_close(&pkg);
    unlink(path);
    unlink(data_path);
}

/* A failed open does not leave the file for bpak_pkg_close */
static void test_open_failure(void **state)
{
    (void)state;
    struct bpak_package pkg;
    char path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_file(path, 4096);

    rc = bpak_pkg_open(&pkg, path, "rb");
    assert_int_equal(rc, -BPAK_BAD_MAGIC);
    assert_null(pkg.fp);
    bpak_pkg_close(&pkg);

    unlink(path);
}

static void test_sign(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_header before;
    struct bpak_key *key = NULL;
    char path[] = "/tmp/bpak-test-XXXXXX";
    int rc;

    create_package(&pkg, path);
    assert_int_equal(pkg.header.signature_kind, BPAK_SIGN_PRIME256v1);

    /* The signature kind is the kind of the key */
    rc = bpak_pkg_sign(&pkg, TEST_DATA("secp384r1-key-pair.pem"));
    assert_int_equal(rc, BPAK_OK);
    assert_int_equal(pkg.header.signature_kind, BPAK_SIGN_SECP384r1);

    rc = bpak_crypto_load_public_key(TEST_DATA("secp384r1-pub-key.der"), &key);
    assert_int_equal(rc, BPAK_OK);
    rc = bpak_pkg_verify(&pkg, key);
    assert_int_equal(rc, BPAK_OK);
    bpak_free(key);

    /* A failed sign leaves the header as it was */
    pkg.header.hash_kind = 99;
    memcpy(&before, &pkg.header, sizeof(before));

    rc = bpak_pkg_sign(&pkg, TEST_DATA("secp256r1-key-pair.pem"));
    assert_int_equal(rc, -BPAK_UNSUPPORTED_HASH_ALG);
    assert_memory_equal(&pkg.header, &before, sizeof(before));

    bpak_pkg_close(&pkg);
    unlink(path);
}

/* The sizes do not wrap around on targets with a 32-bit size_t */
static void test_package_size(void **state)
{
    (void)state;
    struct bpak_package pkg;
    struct bpak_part_header *p;

    memset(&pkg, 0, sizeof(pkg));
    bpak_init_header(&pkg.header);
    assert_int_equal(bpak_add_part(&pkg.header, bpak_id("a"), &p), BPAK_OK);
    p->size = 1000;
    p->pad_bytes = 24;
    assert_int_equal(bpak_pkg_installed_size(&pkg), 1024);
    assert_int_equal(bpak_pkg_size(&pkg), sizeof(struct bpak_header) + 1000);

    /* Two parts of 2^63 bytes */
    p->size = (uint64_t)1 << 63;
    p->pad_bytes = 0;
    assert_int_equal(bpak_add_part(&pkg.header, bpak_id("b"), &p), BPAK_OK);
    p->size = (uint64_t)1 << 63;
    assert_true(bpak_pkg_installed_size(&pkg) == SIZE_MAX);
    assert_true(bpak_pkg_size(&pkg) == SIZE_MAX);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signature_too_large),
        cmocka_unit_test(test_verify_signature_size),
        cmocka_unit_test(test_add_key_allocator),
        cmocka_unit_test(test_add_file_failure),
        cmocka_unit_test(test_add_file_after_transport_part),
        cmocka_unit_test(test_delete_part),
        cmocka_unit_test(test_delete_part_truncated),
        cmocka_unit_test(test_delete_transport_part),
        cmocka_unit_test(test_open_failure),
        cmocka_unit_test(test_sign),
        cmocka_unit_test(test_package_size),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
