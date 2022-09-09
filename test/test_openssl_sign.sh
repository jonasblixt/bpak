# Test: test_openssl_sign
#
# Description: Creates an archive with one data part that is included in the
#  hash context and one that is not. The header hash is exported in binary form
#  and signed using openssl, the signature is then written back.
#
# Purpose: To test externally signing an archive
#
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_openssl_sign
TEST_SRC_DIR=$srcdir
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak
PKG_UUID=0888b0fa-9c48-4524-9845-06a641b61edd

# Create A package
echo Creating package A
rm -f $IMG
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK add $IMG --part data1 \
               --from-file ${TEST_SRC_DIR}/diff2_origin.bin \
               --set-flag dont-hash \
               --encoder merkle $V

$BPAK add $IMG --part data2 \
               --from-file ${TEST_SRC_DIR}/diff2_origin.bin $V

$BPAK show $IMG

$BPAK show $IMG --binary-hash | openssl pkeyutl -sign -inkey ${TEST_SRC_DIR}/secp256r1-key-pair.pem \
                    -keyform PEM > /tmp/sig.data

$BPAK sign $IMG --signature /tmp/sig.data

$BPAK show $IMG $V

$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V

