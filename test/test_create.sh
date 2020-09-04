#!/bin/sh
BPAK=../src/bpak
V=-vvvv
echo Creating simple archive
pwd
set -e

$BPAK --help

IMG_A=vA.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen -t)
set -e

dd if=/dev/urandom of=A bs=1024 count=4096

# Create A package
echo Creating package A
$BPAK create $IMG_A -Y

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG_A --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_A \
                 --encoder uuid -v

$BPAK transport $IMG_A --add --part fs --encoder bsdiff \
                                       --decoder bspatch -v


$BPAK transport $IMG_A --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate

$BPAK add $IMG_A --part fs \
                 --from-file A \
                 --set-flag dont-hash \
                 --encoder merkle -v

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V
echo SIGN
$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem $V
echo SHOW
$BPAK show $IMG_A -vvv
echo VERIFY
$BPAK verify $IMG_A --key $srcdir/secp256r1-pub-key.der -vvv
echo SHOW
$BPAK show $IMG_A --part fs -vvv
$BPAK show $IMG_A --meta bpak-package -vvv
