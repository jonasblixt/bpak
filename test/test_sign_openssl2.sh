#!/bin/sh
BPAK=../src/bpak
V=-vvv
echo Sign test ec256 with openssl
pwd
set -ex

$BPAK create --help
$BPAK show --help
$BPAK sign --help
$BPAK verify --help
$BPAK set --help

IMG=test_keystore.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28
PRI_KEY=$srcdir/secp256r1-key-pair.pem
PUB_KEY=$srcdir/secp256r1-pub-key.der

set -ex

$BPAK create $IMG -Y $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta keystore-provider-id --from-string internal --encoder id

$BPAK add $IMG --part pb-development \
               --from-file $srcdir/dev_rsa_public.der \
               --encoder key $V

$BPAK generate keystore $IMG --name internal $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK show $IMG --binary-hash | openssl pkeyutl -sign -inkey $PRI_KEY \
                    -keyform PEM > /tmp/sig.data

$BPAK sign $IMG --signature /tmp/sig.data $V

$BPAK show $IMG
$BPAK verify $IMG --key $PUB_KEY

# Update keystore and re-sign

$BPAK set $IMG --key-id pb-development \
               --keystore-id bpak-other $V

$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V

$BPAK show $IMG $V
$BPAK verify $IMG --key $PUB_KEY $V

