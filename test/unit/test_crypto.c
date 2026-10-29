#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include "test_helpers.h"

/* sha256("Hello World") */
static const uint8_t hello_world_sha256[] = {
    0xa5, 0x91, 0xa6, 0xd4, 0x0b, 0xf4, 0x20, 0x40, 0x4a, 0x01, 0x17,
    0x33, 0xcf, 0xb7, 0xb1, 0x90, 0xd6, 0x2c, 0x65, 0xbf, 0x0b, 0xcd,
    0xa3, 0x2b, 0x57, 0xb2, 0x77, 0xd9, 0xad, 0x9f, 0x14, 0x6e,
};

static void hash_hello_world(uint8_t *hash, size_t *hash_length)
{
    struct bpak_hash_context ctx;
    const char *test_string = "Hello World";
    int rc;

    rc = bpak_hash_init(&ctx, BPAK_HASH_SHA256);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_hash_update(&ctx,
                          (const uint8_t *)test_string,
                          strlen(test_string));
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_hash_final(&ctx, hash, *hash_length, hash_length);
    assert_int_equal(rc, BPAK_OK);

    bpak_hash_free(&ctx);
}

static void test_sha256(void **state)
{
    (void)state;
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t hash_length = sizeof(hash);

    hash_hello_world(hash, &hash_length);

    assert_int_equal(hash_length, sizeof(hello_world_sha256));
    assert_memory_equal(hash, hello_world_sha256, hash_length);
}

static void test_sign_verify(void **state)
{
    (void)state;
    struct bpak_key *public_key = NULL;
    struct bpak_key *private_key = NULL;
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t hash_length = sizeof(hash);
    uint8_t signature[BPAK_SIGNATURE_MAX_BYTES];
    size_t signature_length = sizeof(signature);
    bool verified = false;
    int rc;

    hash_hello_world(hash, &hash_length);

    rc = bpak_crypto_load_private_key(TEST_DATA("secp256r1-key-pair.pem"),
                                      &private_key);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_crypto_load_public_key(TEST_DATA("secp256r1-pub-key.der"),
                                     &public_key);
    assert_int_equal(rc, BPAK_OK);

    rc = bpak_crypto_sign(hash,
                          hash_length,
                          BPAK_HASH_SHA256,
                          private_key,
                          signature,
                          &signature_length);
    assert_int_equal(rc, BPAK_OK);
    assert_true(signature_length > 0);

    rc = bpak_crypto_verify(signature,
                            signature_length,
                            hash,
                            hash_length,
                            BPAK_HASH_SHA256,
                            public_key,
                            &verified);
    assert_int_equal(rc, BPAK_OK);
    assert_true(verified);

    /* A modified hash must not verify */
    hash[0] ^= 0xff;
    verified = true;
    rc = bpak_crypto_verify(signature,
                            signature_length,
                            hash,
                            hash_length,
                            BPAK_HASH_SHA256,
                            public_key,
                            &verified);
    assert_false(rc == BPAK_OK && verified);

    bpak_free(private_key);
    bpak_free(public_key);
}

static void test_static_key(void **state)
{
    (void)state;
    uint8_t before = 1;
    BPAK_DECLARE_STATIC_KEY(key, 91);
    uint8_t after = 2;

    /* Aligned for struct bpak_key, with room for the data */
    assert_int_equal((uintptr_t)key % __alignof__(struct bpak_key), 0);
    assert_int_equal(key->size, 91);
    memset(key->data, 0xaa, key->size);
    assert_int_equal(before, 1);
    assert_int_equal(after, 2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_static_key),
        cmocka_unit_test(test_sha256),
        cmocka_unit_test(test_sign_verify),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
