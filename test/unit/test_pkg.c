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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signature_too_large),
        cmocka_unit_test(test_verify_signature_size),
        cmocka_unit_test(test_add_key_allocator),
        cmocka_unit_test(test_add_file_failure),
        cmocka_unit_test(test_add_file_after_transport_part),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
