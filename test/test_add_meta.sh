#!/bin/bash
# Test: test_add_meta
#
# Description: Create's metadata from a file
#
# Purpose: To test 'add --meta' command togheter with the --from-file option
#

BPAK=../src/bpak
TEST_NAME=test_add_meta
TEST_SRC_DIR=$1/test
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
set -e

$BPAK --version

IMG=${TEST_NAME}.bpak

dd if=/dev/urandom of=${TEST_NAME}.bin bs=1 count=5

$BPAK create $IMG -Y --hash-kind sha256 --signature-kind prime256v1 $V

$BPAK add $IMG --meta test-meta --from-file ${TEST_NAME}.bin
$BPAK extract $IMG --meta test-meta --output ${TEST_NAME}_dump.bin

first_sha256=$(sha256sum ${TEST_NAME}_dump.bin | cut -d ' ' -f 1)
second_sha256=$(sha256sum ${TEST_NAME}.bin | cut -d ' ' -f 1)

if [ $first_sha256 != $second_sha256  ];
then
    echo "SHA comparison failed $first_sha256 != $second_sha256"
    exit 1
fi
echo $TEST_NAME End
