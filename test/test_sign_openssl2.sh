#!/bin/sh
BPAK=../src/bpak
echo Sign test ec256 with openssl
pwd
set -e

$BPAK create --help
$BPAK show --help
$BPAK sign --help
$BPAK verify --help
$BPAK set --help

IMG=test_keystore.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28
PRI_KEY=$srcdir/secp256r1-key-pair.pem
PUB_KEY=$srcdir/secp256r1-pub-key.der

set -e

$BPAK create $IMG -Y

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid

$BPAK add $IMG --part pb-development \
               --from-file $srcdir/dev_rsa_public.der \
               --encoder key

$BPAK add $IMG --meta bpak-key-id --from-string bpak-test-key --encoder id
$BPAK add $IMG --meta bpak-key-store --from-string bpak-internal --encoder id

$BPAK generate keystore $IMG --name internal

$BPAK show $IMG --hash | openssl pkeyutl -sign -inkey $PRI_KEY \
                    -keyform PEM > /tmp/sig.data

$BPAK sign $IMG --signature /tmp/sig.data --key-id bpak-test-key \
                --key-store bpak-internal

$BPAK show $IMG
$BPAK verify $IMG --key $PUB_KEY

# Update keystore and re-sign

$BPAK set $IMG --meta bpak-key-store --from-string bpak-other --encoder id

$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem \
                  --key-id pb-development \
                  --key-store pb-internal -v

$BPAK show $IMG
$BPAK verify $IMG --key $PUB_KEY

