#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpak/bpak.h>
#include <bpak/bspatch.h>
#include <bpak/id.h>
#include "test_helpers.h"

/* Overrides the weak no-op in libbpak so library logs end up in test output */
int bpak_printf(int verbosity, const char *fmt, ...)
{
    (void)verbosity;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return BPAK_OK;
}

size_t test_load_file(const char *path, uint8_t **buffer_out)
{
    FILE *fp = fopen(path, "rb");
    assert_non_null(fp);

    assert_int_equal(fseek(fp, 0, SEEK_END), 0);
    long length = ftell(fp);
    assert_true(length > 0);
    rewind(fp);

    uint8_t *buffer = malloc(length);
    assert_non_null(buffer);
    assert_int_equal(fread(buffer, 1, length, fp), length);
    fclose(fp);

    *buffer_out = buffer;
    return (size_t)length;
}

#define TEMP_TEMPLATE "/tmp/bpak-test-XXXXXX"

char *test_temp_file(size_t size)
{
    char *path = strdup(TEMP_TEMPLATE);
    int fd;

    assert_non_null(path);
    fd = mkstemp(path);
    assert_true(fd >= 0);

    for (size_t i = 0; i < size; i++)
        assert_int_equal(write(fd, "x", 1), 1);

    close(fd);
    return path;
}

char *test_temp_dir(void)
{
    char *path = strdup(TEMP_TEMPLATE);

    assert_non_null(path);
    assert_non_null(mkdtemp(path));
    return path;
}

void test_remove(char *path)
{
    assert_int_equal(remove(path), 0);
    free(path);
}

#define ALLOC_TAG 0x62706b61u

static unsigned int tagged_allocations;

static void *tagged_calloc(size_t nmemb, size_t size)
{
    uint32_t *p = calloc(1, nmemb * size + 16);

    assert_non_null(p);
    *p = ALLOC_TAG;
    tagged_allocations++;
    return (uint8_t *)p + 16;
}

static void tagged_free(void *ptr)
{
    if (ptr == NULL)
        return;

    uint32_t *p = (uint32_t *)((uint8_t *)ptr - 16);

    assert_int_equal(*p, ALLOC_TAG);
    assert_true(tagged_allocations > 0);
    tagged_allocations--;
    *p = 0;
    free(p);
}

void test_tagged_allocator_begin(void)
{
    tagged_allocations = 0;
    assert_int_equal(bpak_set_calloc_free(tagged_calloc, tagged_free), BPAK_OK);
}

unsigned int test_tagged_allocator_end(void)
{
    assert_int_equal(bpak_set_calloc_free(calloc, free), BPAK_OK);
    return tagged_allocations;
}

void test_put_ctrl(uint8_t *buf, int64_t value)
{
    uint64_t magnitude = value < 0 ? -(uint64_t)value : (uint64_t)value;

    for (int i = 0; i < 8; i++)
        buf[i] = (magnitude >> (8 * i)) & 0xff;

    if (value < 0)
        buf[7] |= 0x80;
}

size_t test_put_ctrl_triple(uint8_t *buf, int64_t diff, int64_t extra,
                            int64_t adjust)
{
    test_put_ctrl(&buf[0], diff);
    test_put_ctrl(&buf[8], extra);
    test_put_ctrl(&buf[16], adjust);
    return BPAK_BSPATCH_CTRL_BUFFER_LENGTH;
}

struct bpak_meta_header *test_add_meta_value(struct bpak_header *h,
                                             bpak_id_t id, bpak_id_t part_ref,
                                             const void *value, uint16_t size)
{
    struct bpak_meta_header *meta;
    int rc;

    rc = bpak_add_meta(h, id, part_ref, size, &meta);
    assert_int_equal(rc, BPAK_OK);
    memcpy(bpak_get_meta_ptr(h, meta, uint8_t), value, size);
    return meta;
}

struct bpak_part_header *
test_add_part_with_size(struct bpak_header *h, const char *name, uint64_t size)
{
    struct bpak_part_header *part;
    int rc;

    rc = bpak_add_part(h, bpak_id(name), &part);
    assert_int_equal(rc, BPAK_OK);
    part->size = size;
    return part;
}
