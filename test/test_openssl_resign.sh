#!/bin/sh
BPAK=../src/bpak
echo Sign openssl resign
set -e
V=-vvv

IMG=openssl_resign_test.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

# Create A package
echo Creating package A
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem \
                  --key-id pb-development \
                  --key-store pb-internal $V

$BPAK show $IMG
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der 

echo Re-signing


$BPAK set $IMG --meta bpak-key-id --from-string the-new-id --encoder id
$BPAK set $IMG --meta bpak-key-store --from-string "some-other-keystore" --encoder id

$BPAK show $IMG

$BPAK show $IMG --hash | openssl pkeyutl -sign -inkey $srcdir/secp256r1-key-pair.pem \
                    -keyform PEM > /tmp/sig.data

$BPAK sign $IMG --signature /tmp/sig.data

#$BPAK sign $IMG --signature /tmp/sig.data --key-id the-new-id \
#                --key-store "some-other-keystore"

$BPAK show $IMG

$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der 

