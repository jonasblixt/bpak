#!/bin/sh
# Validate that bpak respects packages that does not carry any 
#  transport encodings
BPAK=../src/bpak
echo ---- $0 ----
set -ex

IMG=transport6
IMG_A="$IMG"_a.bpak
IMG_B="$IMG"_b.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd
V=-vvvv

dd if=/dev/urandom of="$IMG"_data1 bs=1 count=100
dd if=/dev/urandom of="$IMG"_data2 bs=1 count=101

# Create A package
echo --- Creating package A ---
$BPAK create $IMG_A -Y $V

$BPAK add $IMG_A --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG_A --part data1 \
                 --from-file "$IMG"_data1 $V

$BPAK add $IMG_A --part data2 \
                 --from-file "$IMG"_data2 $V

$BPAK set $IMG_A --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_A --key $srcdir/secp256r1-key-pair.pem $V

# Create B package
$BPAK create $IMG_B -Y $V

$BPAK add $IMG_B --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG_B --part data1 \
                 --from-file "$IMG"_data1 $V

$BPAK add $IMG_B --part data2 \
                 --from-file "$IMG"_data2 $V

$BPAK set $IMG_B --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_B --key $srcdir/secp256r1-key-pair.pem $V

# Test Transport encoding / decoding
echo --- Transport encoding ---

$BPAK transport $IMG_B --encode --origin $IMG_A \
                                --output "$IMG"_transport.bpak \
                                $V


echo --- Transport decoding ---

$BPAK transport "$IMG"_transport.bpak --decode \
                                  --origin $IMG_A \
                                  --output "$IMG"_install.bpak \
                                  $V

$BPAK compare $IMG_B "$IMG"_install.bpak $V

#sha256sum $IMG_B
#sha256sum vB_install.bpak
first_sha256=$(sha256sum $IMG_B | cut -d ' ' -f 1)
second_sha256=$(sha256sum "$IMG"_install.bpak | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show "$IMG"_transport.bpak $V
$BPAK show $IMG_B $V
