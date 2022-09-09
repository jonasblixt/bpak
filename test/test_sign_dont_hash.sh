# Test: test_sign_dont_hash
#
# Description: This test creates an archive with a data block that has the
#  'dont-hash' bit set, which excludes it from the payload hash context.
#
# Purpose: To test that the 'dont-hash' bit actually excludes the part from
#   the payload hash context.
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_sign_dont_hash
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid -v

$BPAK add $IMG --part some-data \
                 --from-file $TEST_SRC_DIR/test_data.bin \
                 --set-flag dont-hash

$BPAK set $IMG --key-id pb-development \
                 --keystore-id pb-internal $V

$BPAK sign $IMG --key $srcdir/secp256r1-key-pair.pem $V
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V

# Introduce a corruption in part 'some-data'

# The data is located just after the header at an offset of 4KiB, write some
#  zeros in the begining.
dd if=/dev/zero of=$IMG bs=1 seek=4096 count=16 conv=notrunc

# It should still verify OK
$BPAK verify $IMG --key $srcdir/secp256r1-pub-key.der $V
