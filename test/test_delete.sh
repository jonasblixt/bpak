#!/bin/bash
# Test: test_delete
#
# Description: This test creates an archive with data and meta data and
#  then tests the 'delete' command
#
# Purpose: To ensure that the delete command can delete part data and meta
#  data from an archive
#

BPAK=../src/bpak
TEST_NAME=test_delete
TEST_SRC_DIR=$1/test
source $TEST_SRC_DIR/common.sh
V=-vvv
echo $TEST_NAME Begin
echo $TEST_SRC_DIR
set -e

$BPAK --version

IMG1=${TEST_NAME}1.bpak
IMG2=${TEST_NAME}2.bpak
IMG1c=${TEST_NAME}1copy.bpak
IMG4=${TEST_NAME}4.bpak

create_data ${TEST_NAME}_data1.bin 134
create_data ${TEST_NAME}_data2.bin 76

# Simple tests without metadata
$BPAK create $IMG1 -Y $V
$BPAK create $IMG2 -Y $V

$BPAK add $IMG1 --part test1 --from-file ${TEST_NAME}_data1.bin $V
$BPAK add $IMG1 --part test2 --from-file ${TEST_NAME}_data2.bin $V

$BPAK add $IMG2 --part test2 --from-file ${TEST_NAME}_data2.bin $V

img1_hash=$($BPAK show -H $IMG1)
img2_hash=$($BPAK show -H $IMG2)

if [ $img1_hash == $img2_hash ];
then
    echo "Hash comparison succeeded when it should not"
    exit 1
fi

# Test case 1, remove part
cp $IMG1 $IMG1c
$BPAK delete $IMG1c --part test1 $V

img1_hash=$($BPAK show -H $IMG1c)
img2_hash=$($BPAK show -H $IMG2)

if [ $img1_hash != $img2_hash ];
then
    echo "Hash comparison failed $img1_hash != $img2_hash"
    exit 1
fi

# Test case 2, remove all parts
cp $IMG1 $IMG1c
$BPAK delete $IMG1c --all $V

img1_hash=$($BPAK show -H $IMG1c)

if [ $img1_hash != "7d0bbb3b969c6cef24969b5e23a9de85b855784a64610243f8f0ddd5ed6773d0" ];
then
    echo "Hash comparison failed $img1_hash != 7d0bbb3b969c6cef24969b5e23a9de85b855784a64610243f8f0ddd5ed6773d0"
    exit 1
fi

# Add metadata to test files
$BPAK add $IMG1 --meta "meta1" --from-string "0x11" --encoder integer $V
$BPAK add $IMG1 --meta "part1-meta2" --part-ref test1 --from-string "0x22" --encoder integer $V
$BPAK add $IMG1 --meta "part2-meta3" --part-ref test2 --from-string "0x33" --encoder integer $V
$BPAK add $IMG1 --meta "meta4" --from-string "0x44" --encoder integer $V

$BPAK add $IMG2 --meta "meta1" --from-string "0x11" --encoder integer $V
$BPAK add $IMG2 --meta "part2-meta3" --part-ref test2 --from-string "0x33" --encoder integer $V
$BPAK add $IMG2 --meta "meta4" --from-string "0x44" --encoder integer $V

# Test case 3, remove part test1
cp $IMG1 $IMG1c
$BPAK delete $IMG1c --part test1 $V

img1_hash=$($BPAK show -H $IMG1c)
img2_hash=$($BPAK show -H $IMG2)

if [ $img1_hash != $img2_hash ];
then
    echo "Hash comparison failed $img1_hash != $img2_hash"
    exit 1
fi

# Test case 4, Remove all parts one by one from the end

$BPAK create $IMG4 -Y $V

$BPAK add $IMG4 --part test1 --from-file ${TEST_NAME}_data1.bin $V
$BPAK add $IMG4 --part test2 --from-file ${TEST_NAME}_data2.bin $V

$BPAK delete $IMG4 --part test2 $V
$BPAK delete $IMG4 --part test1 $V
$BPAK show $IMG4

