# Test: test_transport5
#
# Description: Create archives with multiple parts that should be diffed/patched
#
# Purpose: To test that diffing/patching works on archives that have many
#   parts that shoule be diffed
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_transport5
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG_O=${TEST_NAME}_origin.bpak
IMG_T=${TEST_NAME}_target.bpak
IMG_P=${TEST_NAME}_patch.bpak
IMG_I=${TEST_NAME}_install.bpak

PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

$BPAK create $IMG_O -Y $V

$BPAK add $IMG_O --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK transport $IMG_O --add --part p0 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_O --add --part p1 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_O --add --part p2 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK add $IMG_O --part p0 \
                 --from-file $TEST_SRC_DIR/diff2_origin.bin $V

$BPAK add $IMG_O --part p1 \
                 --from-file $TEST_SRC_DIR/diff2_origin.bin $V

$BPAK add $IMG_O --part p2 \
                 --from-file $TEST_SRC_DIR/diff2_origin.bin $V

$BPAK add $IMG_O --part p3 \
                 --from-file $TEST_SRC_DIR/diff4_origin.bin $V

$BPAK set $IMG_O --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_O --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

# Create target package
$BPAK create $IMG_T -Y $V

$BPAK add $IMG_T --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK transport $IMG_T --add --part p0 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_T --add --part p1 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK transport $IMG_T --add --part p2 --encoder bsdiff \
                                        --decoder bspatch $V

$BPAK add $IMG_T --part p0 \
                 --from-file $TEST_SRC_DIR/diff2_target.bin $V

$BPAK add $IMG_T --part p1 \
                 --from-file $TEST_SRC_DIR/diff2_target.bin $V

$BPAK add $IMG_T --part p2 \
                 --from-file $TEST_SRC_DIR/diff2_target.bin $V

$BPAK add $IMG_T --part p3 \
                 --from-file $TEST_SRC_DIR/diff4_target.bin $V

$BPAK set $IMG_T --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG_T --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

# Test Transport encoding / decoding
echo --- Transport encoding ---

$BPAK transport $IMG_T --encode --origin $IMG_O \
                                --output $IMG_P \
                                $V

echo --- Transport decoding ---

$BPAK transport $IMG_P --decode \
                      --origin $IMG_O \
                      --output $IMG_I \
                      $V

$BPAK compare $IMG_T $IMG_I $V

first_sha256=$(sha256sum $IMG_T | cut -d ' ' -f 1)
second_sha256=$(sha256sum $IMG_I | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi

$BPAK show $IMG_P $V
$BPAK show $IMG_T $V
