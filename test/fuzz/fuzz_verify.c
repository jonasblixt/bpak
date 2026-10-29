/*
 * Package verification of untrusted packages.
 *
 * Input: a package, the header followed by the payload. The verification
 * key is selected by the signature kind of the header.
 */

#define _GNU_SOURCE /* fmemopen */
#include <stdio.h>
#include <string.h>
#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include <bpak/pkg.h>
#include <bpak/verify.h>
#include "fuzz.h"

struct payload {
    const uint8_t *data;
    size_t size;
};

static ssize_t read_payload(off_t offset, uint8_t *buffer, size_t length,
                            void *user)
{
    struct payload *p = user;

    if (offset < 0 || (size_t)offset > p->size ||
        length > p->size - (size_t)offset)
        return -BPAK_READ_ERROR;

    memcpy(buffer, &p->data[offset], length);
    return length;
}

static struct bpak_key *load_key(const char *name)
{
    char path[1024];
    struct bpak_key *key = NULL;

    snprintf(path, sizeof(path), "%s/%s", BPAK_FUZZ_KEY_DIR, name);
    FUZZ_ASSERT(bpak_crypto_load_public_key(path, &key) == BPAK_OK);
    return key;
}

static struct bpak_key *signature_key(uint8_t signature_kind)
{
    static struct bpak_key *keys[BPAK_SIGN_SECP521r1 + 1];

    if (keys[BPAK_SIGN_PRIME256v1] == NULL) {
        keys[BPAK_SIGN_RSA4096] = load_key("dev_rsa_public.der");
        keys[BPAK_SIGN_PRIME256v1] = load_key("secp256r1-pub-key.der");
        keys[BPAK_SIGN_SECP384r1] = load_key("secp384r1-pub-key.der");
        keys[BPAK_SIGN_SECP521r1] = load_key("secp521r1-pub-key.der");
    }

    if (signature_kind < BPAK_SIGN_RSA4096 ||
        signature_kind > BPAK_SIGN_SECP521r1)
        return keys[BPAK_SIGN_PRIME256v1];

    return keys[signature_kind];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct bpak_package *pkg = calloc(1, sizeof(*pkg));
    struct payload payload = { .data = data, .size = size };
    uint8_t hash[BPAK_HASH_MAX_LENGTH];
    size_t hash_size = sizeof(hash);

    FUZZ_ASSERT(pkg != NULL);

    if (size < sizeof(pkg->header))
        goto out;

    /* As bpak_pkg_open */
    memcpy(&pkg->header, data, sizeof(pkg->header));

    if (bpak_valid_header(&pkg->header) != BPAK_OK)
        goto out;

    /* The library function, with the package in memory */
    pkg->fp = fmemopen((void *)data, size, "rb");
    FUZZ_ASSERT(pkg->fp != NULL);
    (void)bpak_pkg_verify(pkg, signature_key(pkg->header.signature_kind));
    fclose(pkg->fp);
    pkg->fp = NULL;

    /* The payload, also when the signature does not match */
    (void)bpak_verify_payload(&pkg->header,
                              read_payload,
                              sizeof(pkg->header),
                              &payload);

    /* The merkle trees are only verified when the payload hash matches */
    if (bpak_verify_compute_payload_hash(&pkg->header,
                                         read_payload,
                                         sizeof(pkg->header),
                                         &payload,
                                         hash,
                                         &hash_size) == BPAK_OK &&
        hash_size <= sizeof(pkg->header.payload_hash)) {
        memcpy(pkg->header.payload_hash, hash, hash_size);
        (void)bpak_verify_payload(&pkg->header,
                                  read_payload,
                                  sizeof(pkg->header),
                                  &payload);
    }

out:
    free(pkg);
    return 0;
}
