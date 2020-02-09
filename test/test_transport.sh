#!/bin/sh
BPAK=../src/bpak
echo Creating simple archive
set -e

$BPAK --help

IMG_A=vA.bpak
IMG_B=vB.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
PKG_UNIQUE_ID_A=$(uuidgen -t)
PKG_UNIQUE_ID_B=$(uuidgen -t)
set -e

dd if=/dev/urandom of=A bs=1024 count=4096
dd if=/dev/urandom of=B_ bs=1024 count=1024

cat A B_ > B

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

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem \
                  --key-id pb-development \
                  --key-store pb-internal -v

# Create B package
echo Creating package B
$BPAK create $IMG_B -Y

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID --encoder uuid -v
$BPAK add $IMG_B --meta bpak-package-uid --from-string $PKG_UNIQUE_ID_B \
                 --encoder uuid -v

$BPAK transport $IMG_B --add --part fs --encoder bsdiff \
                                       --decoder bspatch -v


$BPAK transport $IMG_B --add --part fs-hash-tree \
                       --encoder remove-data \
                       --decoder merkle-generate

$BPAK add $IMG_B --part fs \
                 --from-file B \
                 --set-flag dont-hash \
                 --encoder merkle -v

$BPAK sign $IMG_B --key $srcdir/secp256r1-key-pair.pem \
                  --key-id pb-development \
                  --key-store pb-internal -v

# Test Transport encoding / decoding
echo Transport encoding
cp $IMG_B vB_transport.bpak

$BPAK transport vB_transport.bpak --encode --origin $IMG_A -vvv

cp vB_transport.bpak vB_install.bpak

echo Transport decoding

$BPAK transport vB_install.bpak --decode --origin $IMG_A -vvv

$BPAK compare vB.bpak vB_install.bpak -vv

#sha256sum $IMG_B
#sha256sum vB_install.bpak
first_sha256=$(sha256sum vB.bpak | cut -d ' ' -f 1)
second_sha256=$(sha256sum vB_install.bpak | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show vB_transport.bpak -vvv
$BPAK show vB.bpak -vvv
