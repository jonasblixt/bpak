# Test: test_dep_version
#
# Description: This test creates an archive with a few 'bpak-dependency'
#  meta data's
#
# Purpose: To test package uuid + semver string decoder
#

#!/bin/bash
BPAK=../src/bpak
TEST_NAME=test_dep_version
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

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid $V

$BPAK add $IMG --meta bpak-version --from-string "1.2.3" $V
echo Adding first dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string "f862352d-2444-41c2-96d8-538de6442162:>=0.1.0 <1.0.0" \
               $V
echo Adding second dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string "3d7eda1e-a4b3-431b-abf6-1cff2e21f9db:>=2.1.0 <3.0.0" \
               $V

echo Adding third dep
$BPAK add $IMG --meta bpak-dependency \
               --from-string "3d7eda1e-a4b3-431b-abf6-1cff2e21f9db:>3.1.0 <4.0.0" \
               $V

$BPAK show $IMG $V
