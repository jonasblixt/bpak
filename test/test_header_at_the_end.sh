#!/bin/sh
BPAK=../src/bpak
V=-vvvv
echo Creating simple archive
pwd
set -e

$BPAK --help

IMG_A=header_at_the_end.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen)
set -e

dd if=/dev/urandom of=A bs=1024 count=4096
dd if=/dev/urandom of=random_data bs=1024 count=4

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

$BPAK add $IMG_A --part random \
                 --from-file random_data

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

DAT=header_at_the_end.dat

dd if=/dev/zero of=$DAT bs=1M count=8
# Extract header
dd if=$IMG_A of=header_at_the_end.header bs=1024 count=4
# Extract data
dd if=$IMG_A of=header_at_the_end.data bs=1024 skip=4
# Implant the header at the last 4k of $DAT
dd if=header_at_the_end.header of=$DAT bs=1024 seek=8188 count=4
# Implant the data at the beginning of $DAT
dd if=header_at_the_end.data of=$DAT bs=1024 conv=notrunc

$BPAK verify $DAT --key $srcdir/secp256r1-pub-key.der -vvv
