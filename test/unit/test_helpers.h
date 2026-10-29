#ifndef BPAK_TEST_HELPERS_H
#define BPAK_TEST_HELPERS_H

/* cmocka.h depends on these being included first */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <bpak/bpak.h>

/* Absolute path to a file in test/data */
#define TEST_DATA(name) BPAK_TEST_DATA_DIR "/" name

/* Read a whole file into a malloc'd buffer. Fails the test on error. */
size_t test_load_file(const char *path, uint8_t **buffer_out);

/* Create a temporary file with 'size' bytes of 'x' and return its malloc'd
 * path. Remove it with test_remove. */
char *test_temp_file(size_t size);

/* Create a temporary directory and return its malloc'd path. Remove it
 * with test_remove. */
char *test_temp_dir(void);

/* Remove a temporary file or empty directory and free its path */
void test_remove(char *path);

/* Make the library allocate with an allocator that tags its allocations,
 * freeing anything else fails the test */
void test_tagged_allocator_begin(void);

/* Restore calloc and free, returns the number of tagged allocations that
 * were not freed */
unsigned int test_tagged_allocator_end(void);

/* Write a bspatch control value: sign and magnitude, little endian */
void test_put_ctrl(uint8_t *buf, int64_t value);

/* Write a bspatch control triple, returns its length */
size_t test_put_ctrl_triple(uint8_t *buf, int64_t diff, int64_t extra,
                            int64_t adjust);

/* Add meta data with the 'size' bytes of 'value'. Fails the test on error. */
struct bpak_meta_header *test_add_meta_value(struct bpak_header *h,
                                             bpak_id_t id, bpak_id_t part_ref,
                                             const void *value, uint16_t size);

/* Add a part of 'size' bytes. Fails the test on error. */
struct bpak_part_header *
test_add_part_with_size(struct bpak_header *h, const char *name, uint64_t size);

#endif
