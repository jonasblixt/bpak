#!/bin/sh
BPAK=../src/bpak
V=-vvv
echo Sign test ec256 with openssl
pwd
set -e

$BPAK create --help
$BPAK show --help
$BPAK sign --help
$BPAK verify --help

IMG=test_keystore_openssl.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28
PRI_KEY=$srcdir/secp256r1-key-pair.pem
PUB_KEY=$srcdir/secp256r1-pub-key.der

set -e

$BPAK create $IMG -Y

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid

$BPAK add $IMG --part pb-development \
               --from-file $srcdir/dev_rsa_public.der \
               --encoder key

$BPAK set $IMG --key-id bpak-test-key \
               --keystore-id bpak-internal $V

$BPAK generate keystore $IMG --name internal

$BPAK show $IMG --hash | openssl pkeyutl -sign -inkey $PRI_KEY \
                    -keyform PEM > /tmp/sig_openssl.data

echo SHOW1
$BPAK show $IMG $V

echo SIGNING
$BPAK sign $IMG --signature /tmp/sig_openssl.data $V

echo SHOW2
$BPAK show $IMG $V

echo VERIFY
$BPAK verify $IMG --key $PUB_KEY $V
echo TEST END
