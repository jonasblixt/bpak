#!/bin/bash
# Test: test_corrupt_payload2
#
# Description: This test creates an archive with a data block, signs the 
# archive and then introduces a corruption in the data part.
#
# Purpose: To ensure that the verify function detects the corrupt portion.
#

BPAK=../src/bpak
TEST_NAME=test_corrupt_payload2
TEST_SRC_DIR=$1/test
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

create_data ${TEST_NAME}_data.bin 128

echo $TEST_NAME Creating package
$BPAK create $IMG -Y $V
$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --part fs \
                 --from-file ${TEST_NAME}_data.bin $V

$BPAK set $IMG --key-id pb-development \
                 --keystore-id pb-internal $V
echo SIGN
$BPAK sign $IMG --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V
echo VERIFY
$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V

# Introduce corruption in the data part, the data is located just after the header
#  at an offset of 4KiB, write some zeros in the begining.
dd if=/dev/zero of=$IMG bs=1 seek=4096 count=16 conv=notrunc
set +e
echo VERIFY
$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V
result_code=$?
if [ $result_code -ne 232 ];
then
    exit $result_code
fi

echo $TEST_NAME End
