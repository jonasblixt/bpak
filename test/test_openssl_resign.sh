# Test: test_openssl_resign
#
# Description: Creates an archive and signs it using the build in sign command.
#  Then the key-id and keystore-id are changed and the archive is re-signed
#  using openssl externally
#
# Purpose: To test externally signing an archive
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_openssl_resign
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
$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK set $IMG --key-id pb-development \
               --keystore-id pb-internal $V

$BPAK sign $IMG --key $TEST_SRC_DIR/secp256r1-key-pair.pem $V

$BPAK show $IMG $V
$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V

echo Re-signing

$BPAK set $IMG --key-id the-new-id \
               --keystore-id some-other-keystore $V

$BPAK show $IMG $V

$BPAK show $IMG --binary-hash | openssl pkeyutl -sign -inkey $TEST_SRC_DIR/secp256r1-key-pair.pem \
                    -keyform PEM > ${TEST_NAME}_sig.data

$BPAK sign $IMG --signature ${TEST_NAME}_sig.data

$BPAK show $IMG $V

$BPAK verify $IMG --key $TEST_SRC_DIR/secp256r1-pub-key.der $V


