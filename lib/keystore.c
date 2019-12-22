#include <bpak/bpak.h>
#include <bpak/crypto.h>
#include <bpak/keystore.h>


/*

RSA4096:

  0 546: SEQUENCE {
  4  13:   SEQUENCE {
  6   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 17   0:     NULL
       :     }
 19 527:   BIT STRING, encapsulates {
 24 522:     SEQUENCE {
 28 513:       INTEGER
       :         00 A6 DE 6E 59 56 9D A1 E5 9F 4C 72 E2 6D 7B BF
                            ....
545   3:       INTEGER 65537
       :       }
       :     }
       :   }

prime521r1:

  0 155: SEQUENCE {
  3  16:   SEQUENCE {
  5   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 14   5:     OBJECT IDENTIFIER secp521r1 (1 3 132 0 35)
       :     }
 21 134:   BIT STRING
       :     04 00 2E 8C AE C2 F8 28 A6 67 F1 0C 43 05 F5 A2
                ......
       :     07 04 AF AA 33
       :   }

30 81 9b
    30 10
        06 07 2a  86 48 ce 3d 02 01
        06 05 2b 81 04 00 23 
    03 81 86  00 04 00 2e 8c ae c2 .....


prime256v1:
 
  0  89: SEQUENCE {
  2  19:   SEQUENCE {
  4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
 13   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :     }
 23  66:   BIT STRING
       :     04 43 75 53 46 77 1F 31 36 17 99 72 CC 7A D2 B0
                ......
       :     9E
       :   }

30 59
    30 13 
        06 07 2a 86  48 ce 3d 02 01 
        06 08 2a 86 48 ce 3d 03 01 07 
    03  42 00 04 43 75 53 46 77 ...
 */

static int asn1_sz(uint8_t *buf, size_t *sz, uint8_t *pos)
{
    if ((*buf) & 0x80 == 0)
    {
        *pos = 1;
        *sz = *buf;
        return BPAK_OK;
    }

    return BPAK_OK;
}

int bpak_parse_key(const struct bpak_key *k, uint8_t *buf, size_t sz)
{
    uint32_t pos = 0;
    uint8_t consumed;
    int rc;

    /* Check first sequence */
    if (buf[pos++] != 0x30)
        return -BPAK_FAILED;

    size_t seq_sz = 0;

    rc = asn1_sz(&buf[pos], &seq_sz, &consumed);

    if (rc != BPAK_OK)
        return rc;

    pos += consumed;

    /* Check sequence tag */
    if (buf[pos++] != 0x30)
        return -BPAK_FAILED;

    /* Decode sequence size */
    rc = asn1_sz(&buf[pos], &seq_sz, &consumed);

    if (rc != BPAK_OK)
        return rc;

    pos += consumed;
}

int bpak_keystore_get(struct bpak_keystore *ks, uint8_t id,
                        struct bpak_key **k)
{
    *k = NULL;

    if (!ks->verified)
        return -BPAK_FAILED;

    for (int i = 0; i < ks->no_of_keys; i++)
    {
        if (ks->keys[i]->id == id)
        {
            *k = ks->keys[i];
            break;
        }
    }

    if (*k)
        return BPAK_OK;

    return -BPAK_FAILED;
}
