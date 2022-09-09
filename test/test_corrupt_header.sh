# Test: test_corrupt_header
#
# Description: This test creates an empty archive , signs the archive and then
# introduces a corruption in the header
#
# Purpose: To ensure that the verify function correctly detects corruptions
# in the header
#!/bin/bash

BPAK=../src/bpak
TEST_NAME=test_corrupt_header
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

echo $TEST_NAME Creating package
$BPAK create $IMG -Y $V
$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK set $IMG --key-id pb-development \
                 --keystore-id pb-internal $V
echo SIGN
$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V
echo VERIFY
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V

# Introduce corruption in the meta data array
dd if=/dev/zero of=$IMG bs=1 seek=8 count=16 conv=notrunc
set +e
echo VERIFY, should fail
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V
result_code=$?
if [ $result_code -ne 236 ];
then
    exit $result_code
fi

echo $TEST_NAME End
