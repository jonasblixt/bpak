#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include <bpak/keystore.h>

#include <mbedtls/pk.h>

#include "nala.h"

/* NIST EC256p public key */
struct bpak_key key0 = {
    .id = 0,
    .size = 91,
    .kind = BPAK_KEY_PUB_PRIME256v1,
    .data =
        {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
            0x07, 0x03, 0x42, 0x00, 0x04, 0x43, 0x75, 0x53, 0x46, 0x77, 0x1f,
            0x31, 0x36, 0x17, 0x99, 0x72, 0xcc, 0x7a, 0xd2, 0xb0, 0x91, 0x0d,
            0x58, 0xd3, 0x93, 0x2e, 0x9a, 0x9e, 0x42, 0x35, 0x2d, 0x45, 0x11,
            0x56, 0x12, 0x64, 0xaa, 0xe0, 0xad, 0x98, 0x8f, 0x89, 0x11, 0xa8,
            0xbb, 0xd1, 0xf6, 0x4f, 0x2c, 0xa8, 0xa6, 0x33, 0x1d, 0xd0, 0x82,
            0x18, 0xa5, 0x15, 0xad, 0x71, 0x82, 0xec, 0x68, 0xb2, 0xae, 0xc2,
            0xbf, 0x80, 0x9e,
        },
};

/* NIST EC256p private key */
struct bpak_key key1 = {
    .id = 1,
    .size = 121,
    .kind = BPAK_KEY_PRI_PRIME256v1,
    .data = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x1e, 0x55, 0x66, 0x35,
             0xbe, 0x3f, 0xa3, 0x6d, 0x54, 0x97, 0x33, 0x66, 0xe8, 0x1b, 0x54,
             0x01, 0x2b, 0x9b, 0x15, 0x33, 0x38, 0x4a, 0xd8, 0x3a, 0xf0, 0x81,
             0x10, 0x2e, 0xa5, 0xdf, 0xeb, 0xbe, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
             0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
             0x00, 0x04, 0x43, 0x75, 0x53, 0x46, 0x77, 0x1f, 0x31, 0x36, 0x17,
             0x99, 0x72, 0xcc, 0x7a, 0xd2, 0xb0, 0x91, 0x0d, 0x58, 0xd3, 0x93,
             0x2e, 0x9a, 0x9e, 0x42, 0x35, 0x2d, 0x45, 0x11, 0x56, 0x12, 0x64,
             0xaa, 0xe0, 0xad, 0x98, 0x8f, 0x89, 0x11, 0xa8, 0xbb, 0xd1, 0xf6,
             0x4f, 0x2c, 0xa8, 0xa6, 0x33, 0x1d, 0xd0, 0x82, 0x18, 0xa5, 0x15,
             0xad, 0x71, 0x82, 0xec, 0x68, 0xb2, 0xae, 0xc2, 0xbf, 0x80, 0x9e},
};

struct bpak_keystore internal = {.id = 0x9dd4db42, /* bpak-internal-keystore*/
                                 .no_of_keys = 2,
                                 .verified = true,
                                 .keys = {
                                     &key0,
                                     &key1,
                                 }};

TEST(crypto_sha256)
{
    int rc;
    struct bpak_hash_context ctx;
    const char *test_string = "Hello World";
    const char *expected_hash = "\xa5\x91\xa6\xd4\x0b\xf4\x20\x40"
                                "\x4a\x01\x17\x33\xcf\xb7\xb1\x90"
                                "\xd6\x2c\x65\xbf\x0b\xcd\xa3\x2b"
                                "\x57\xb2\x77\xd9\xad\x9f\x14\x6e";
    char hash[32];

    rc = bpak_hash_init(&ctx, BPAK_HASH_SHA256);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_hash_update(&ctx, (void *)test_string, strlen(test_string));
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_hash_out(&ctx, hash, 32);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_MEMORY(hash, expected_hash, 32);

    rc = bpak_hash_free(&ctx);
    ASSERT_EQ(rc, BPAK_OK);
}

TEST(crypto_sign_verify)
{
    struct bpak_key *key = NULL;
    struct bpak_key *sign_key = NULL;
    int rc;

    struct bpak_hash_context hash_ctx;
    const char *test_string = "Hello World";
    const char *expected_hash = "\xa5\x91\xa6\xd4\x0b\xf4\x20\x40"
                                "\x4a\x01\x17\x33\xcf\xb7\xb1\x90"
                                "\xd6\x2c\x65\xbf\x0b\xcd\xa3\x2b"
                                "\x57\xb2\x77\xd9\xad\x9f\x14\x6e";

    char hash[32];

    rc = bpak_hash_init(&hash_ctx, BPAK_HASH_SHA256);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_hash_update(&hash_ctx, (void *)test_string, strlen(test_string));
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_hash_out(&hash_ctx, hash, 32);
    ASSERT_EQ(rc, BPAK_OK);
    ASSERT_MEMORY(hash, expected_hash, 32);

    rc = bpak_keystore_get(&internal, 0, &key);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_keystore_get(&internal, 1, &sign_key);
    ASSERT_EQ(rc, BPAK_OK);

    uint8_t sig[128];
    size_t size = 128;

    /* Create signature */

    struct bpak_sign_context ctx_sign;
    rc = bpak_sign_init(&ctx_sign, sign_key);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_sign(&ctx_sign, &hash_ctx, sig, &size);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_sign_free(&ctx_sign);
    ASSERT_EQ(rc, BPAK_OK);
    /* Verify signature */
    struct bpak_sign_context ctx;

    rc = bpak_sign_init(&ctx, key);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_verify(&ctx, &hash_ctx, sig, size);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_sign_free(&ctx);
    ASSERT_EQ(rc, BPAK_OK);

    rc = bpak_hash_free(&hash_ctx);
    ASSERT_EQ(rc, BPAK_OK);
}
