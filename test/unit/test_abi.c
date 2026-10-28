/*
 * ABI and on-disk format of bpak.
 *
 * Packages, patches and keystores created by one version of bpak are read
 * by other versions, for example by bootloaders that are never updated.
 * The values in this file are therefore fixed forever: a failing test
 * here means that a change breaks compatibility. Never update an expected
 * value to make a test pass, change the code instead. New fields, enum
 * values and ids are added to the tables below.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/id.h>
#include <bpak/utils.h>
#include <bpak/key.h>
#include <bpak/keystore.h>
#include <bpak/merkle.h>
#include <bpak/bspatch.h>
#include <bpak/heatshrink_decoder.h>
#include "test_helpers.h"

struct expected_value {
    const char *name;
    long long actual;
    long long expected;
};

static void check_values(const struct expected_value *values, size_t count)
{
    bool ok = true;

    for (size_t i = 0; i < count; i++) {
        if (values[i].actual != values[i].expected) {
            print_error("%s is %lld, expected %lld\n",
                        values[i].name,
                        values[i].actual,
                        values[i].expected);
            ok = false;
        }
    }

    assert_true(ok);
}

#define CHECK_VALUES(_values)                                                \
    check_values(_values, sizeof(_values) / sizeof(_values[0]))

#define VALUE(_value, _expected) { #_value, (long long)(_value), _expected }

/* Offset and size of a struct member */
#define FIELD(_type, _member, _offset, _size)                                \
    VALUE(offsetof(struct _type, _member), _offset),                         \
    VALUE(sizeof(((struct _type *)0)->_member), _size)

static void test_header_layout(void **state)
{
    (void)state;
    const struct expected_value values[] = {
        VALUE(sizeof(struct bpak_header), 4096),
        FIELD(bpak_header, magic, 0, 4),
        FIELD(bpak_header, pad0, 4, 4),
        FIELD(bpak_header, meta, 8, 512),
        FIELD(bpak_header, parts, 520, 1024),
        FIELD(bpak_header, metadata, 1544, 1920),
        FIELD(bpak_header, hash_kind, 3464, 1),
        FIELD(bpak_header, signature_kind, 3465, 1),
        FIELD(bpak_header, alignment, 3466, 2),
        FIELD(bpak_header, payload_hash, 3468, 64),
        FIELD(bpak_header, key_id, 3532, 4),
        FIELD(bpak_header, keystore_id, 3536, 4),
        FIELD(bpak_header, pad1, 3540, 42),
        FIELD(bpak_header, signature, 3582, 512),
        FIELD(bpak_header, signature_sz, 4094, 2),

        VALUE(sizeof(struct bpak_meta_header), 16),
        FIELD(bpak_meta_header, id, 0, 4),
        FIELD(bpak_meta_header, size, 4, 2),
        FIELD(bpak_meta_header, offset, 6, 2),
        FIELD(bpak_meta_header, part_id_ref, 8, 4),
        FIELD(bpak_meta_header, pad, 12, 4),

        VALUE(sizeof(struct bpak_part_header), 32),
        FIELD(bpak_part_header, id, 0, 4),
        FIELD(bpak_part_header, size, 4, 8),
        FIELD(bpak_part_header, offset, 12, 8),
        FIELD(bpak_part_header, transport_size, 20, 8),
        FIELD(bpak_part_header, pad_bytes, 28, 2),
        FIELD(bpak_part_header, flags, 30, 1),
        FIELD(bpak_part_header, pad, 31, 1),

        VALUE(sizeof(struct bpak_transport_meta), 32),
        FIELD(bpak_transport_meta, alg_id_encode, 0, 4),
        FIELD(bpak_transport_meta, alg_id_decode, 4, 4),
        FIELD(bpak_transport_meta, data, 8, 24),

        VALUE(sizeof(bpak_id_t), 4),
    };

    CHECK_VALUES(values);
}

/* Keystores generated with 'bpak generate keystore' are compiled into
 * bootloaders against these structs */
static void test_keystore_layout(void **state)
{
    (void)state;
    const struct expected_value values[] = {
        VALUE(sizeof(struct bpak_key), 16),
        FIELD(bpak_key, kind, 0, 4),
        FIELD(bpak_key, size, 4, 2),
        FIELD(bpak_key, id, 8, 4),
        FIELD(bpak_key, rz, 12, 4),
        VALUE(offsetof(struct bpak_key, data), 16),

        VALUE(offsetof(struct bpak_keystore, id), 0),
        VALUE(offsetof(struct bpak_keystore, no_of_keys), 4),
        VALUE(offsetof(struct bpak_keystore, verified), 5),
        VALUE(offsetof(struct bpak_keystore, keys), 8),
    };

    CHECK_VALUES(values);
}

static void test_constants(void **state)
{
    (void)state;
    const struct expected_value values[] = {
        VALUE(BPAK_HEADER_MAGIC, 0x42504132),
        VALUE(BPAK_MAX_PARTS, 32),
        VALUE(BPAK_MAX_META, 32),
        VALUE(BPAK_METADATA_BYTES, 1920),
        VALUE(BPAK_PART_ALIGN, 512),
        VALUE(BPAK_META_ALIGN, 8),
        VALUE(BPAK_SIGNATURE_MAX_BYTES, 512),
        VALUE(BPAK_HASH_MAX_LENGTH, 64),
        VALUE(BPAK_FLAG_EXCLUDE_FROM_HASH, 0x01),
        VALUE(BPAK_FLAG_TRANSPORT, 0x02),

        /* Format of merkle hash trees */
        VALUE(BPAK_MERKLE_BLOCK_SZ, 4096),
        VALUE(BPAK_MERKLE_HASH_BYTES, 32),

        /* Format of bsdiff patches */
        VALUE(BPAK_BSPATCH_CTRL_BUFFER_LENGTH, 24),
        VALUE(HEATSHRINK_STATIC_WINDOW_BITS, 8),
        VALUE(HEATSHRINK_STATIC_LOOKAHEAD_BITS, 7),
    };

    CHECK_VALUES(values);
}

static void test_enums(void **state)
{
    (void)state;
    const struct expected_value values[] = {
        VALUE(BPAK_HASH_INVALID, 0),
        VALUE(BPAK_HASH_SHA256, 1),
        VALUE(BPAK_HASH_SHA384, 2),
        VALUE(BPAK_HASH_SHA512, 3),

        VALUE(BPAK_SIGN_INVALID, 0),
        VALUE(BPAK_SIGN_RSA4096, 1),
        VALUE(BPAK_SIGN_PRIME256v1, 2),
        VALUE(BPAK_SIGN_SECP384r1, 3),
        VALUE(BPAK_SIGN_SECP521r1, 4),

        VALUE(BPAK_COMPRESSION_NONE, 0),
        VALUE(BPAK_COMPRESSION_HS, 1),
        VALUE(BPAK_COMPRESSION_LZMA, 2),

        VALUE(BPAK_KEY_INVALID, 0),
        VALUE(BPAK_KEY_PUB_RSA4096, 1),
        VALUE(BPAK_KEY_PUB_PRIME256v1, 2),
        VALUE(BPAK_KEY_PUB_SECP384r1, 3),
        VALUE(BPAK_KEY_PUB_SECP521r1, 4),
        VALUE(BPAK_KEY_PRI_RSA4096, 5),
        VALUE(BPAK_KEY_PRI_PRIME256v1, 6),
        VALUE(BPAK_KEY_PRI_SECP384r1, 7),
        VALUE(BPAK_KEY_PRI_SECP521r1, 8),

        /* Also the exit codes of the bpak tool */
        VALUE(BPAK_OK, 0),
        VALUE(BPAK_FAILED, 1),
        VALUE(BPAK_NOT_FOUND, 2),
        VALUE(BPAK_SIZE_ERROR, 3),
        VALUE(BPAK_NO_SPACE_LEFT, 4),
        VALUE(BPAK_BAD_ALIGNMENT, 5),
        VALUE(BPAK_SEEK_ERROR, 6),
        VALUE(BPAK_NOT_SUPPORTED, 7),
        VALUE(BPAK_NEEDS_MORE_DATA, 8),
        VALUE(BPAK_WRITE_ERROR, 9),
        VALUE(BPAK_DECOMPRESSOR_ERROR, 10),
        VALUE(BPAK_COMPRESSOR_ERROR, 11),
        VALUE(BPAK_PATCH_READ_ORIGIN_ERROR, 12),
        VALUE(BPAK_PATCH_WRITE_ERROR, 13),
        VALUE(BPAK_READ_ERROR, 14),
        VALUE(BPAK_BAD_MAGIC, 15),
        VALUE(BPAK_UNSUPPORTED_HASH_ALG, 16),
        VALUE(BPAK_BUFFER_TOO_SMALL, 17),
        VALUE(BPAK_FILE_NOT_FOUND, 18),
        VALUE(BPAK_KEY_DECODE, 19),
        VALUE(BPAK_VERIFY_FAIL, 20),
        VALUE(BPAK_SIGN_FAIL, 21),
        VALUE(BPAK_UNSUPPORTED_KEY, 22),
        VALUE(BPAK_BAD_ROOT_HASH, 23),
        VALUE(BPAK_BAD_PAYLOAD_HASH, 24),
        VALUE(BPAK_MISSING_META_DATA, 25),
        VALUE(BPAK_PACKAGE_UUID_MISMATCH, 26),
        VALUE(BPAK_UNSUPPORTED_COMPRESSION, 27),
        VALUE(BPAK_KEY_NOT_FOUND, 28),
        VALUE(BPAK_KEYSTORE_ID_MISMATCH, 29),
        VALUE(BPAK_EXISTS, 30),
    };

    CHECK_VALUES(values);
}

/* Ids are CRC32 checksums of names. They are stored in packages, so both
 * the predefined ids and the algorithm that computes them are fixed. */
static void test_ids(void **state)
{
    (void)state;
    const struct {
        const char *name;
        bpak_id_t define;
        bpak_id_t expected;
    } ids[] = {
        { "bpak-transport", BPAK_ID_BPAK_TRANSPORT, 0x2d44bbfb },
        { "merkle-salt", BPAK_ID_MERKLE_SALT, 0x7c9b2f93 },
        { "merkle-root-hash", BPAK_ID_MERKLE_ROOT_HASH, 0xe68fc9be },
        { "keystore-provider-id", BPAK_ID_KEYSTORE_PROVIDER_ID, 0xfb367d9a },
        { "bpak-version", BPAK_ID_BPAK_VERSION, 0x9a5bab69 },
        { "pb-load-addr", BPAK_ID_PB_LOAD_ADDR, 0xd1e64a4b },
        { "bpak-package", BPAK_ID_BPAK_PACKAGE, 0xfb2f1f3f },
        { "bpak-key-id", BPAK_ID_BPAK_KEY_ID, 0x7da19399 },
        { "bpak-key-store", BPAK_ID_BPAK_KEY_STORE, 0x106c13a7 },
        { "bsdiff", BPAK_ID_BSDIFF, 0x9f7aacf9 },
        { "bsdiff-lzma", BPAK_ID_BSDIFF_LZMA, 0x1607e56e },
        { "bsdiff-no-comp", BPAK_ID_BSDIFF_NO_COMP, 0x0a878e3e },
        { "bspatch", BPAK_ID_BSPATCH, 0xb5964388 },
        { "bspatch-lzma", BPAK_ID_BSPATCH_LZMA, 0x933a9893 },
        { "bspatch-no-comp", BPAK_ID_BSPATCH_NO_COMP, 0x75622592 },
        { "merkle-generate", BPAK_ID_MERKLE_GENERATE, 0xb5bcc58f },
        { "remove-data", BPAK_ID_REMOVE_DATA, 0x57004cd0 },
        { "", 0, 0 },
    };
    bool ok = true;

    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        bpak_id_t id = bpak_id(ids[i].name);

        if (id != ids[i].expected || ids[i].define != ids[i].expected) {
            print_error("'%s': bpak_id() = 0x%08x, define = 0x%08x, "
                        "expected 0x%08x\n",
                        ids[i].name,
                        id,
                        ids[i].define,
                        ids[i].expected);
            ok = false;
        }
    }

    /* Merkle hash trees are stored in a part with the id
     * '<part name>-hash-tree' */
    assert_int_equal(bpak_part_name_to_hash_tree_id("fs"), 0x77fadb17);

    assert_true(ok);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_header_layout),
        cmocka_unit_test(test_keystore_layout),
        cmocka_unit_test(test_constants),
        cmocka_unit_test(test_enums),
        cmocka_unit_test(test_ids),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
