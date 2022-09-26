#!/bin/bash

BPAK=../src/bpak
echo Test id generator
set -e

RESULT=$($BPAK generate id bpak-test | cut -d ' ' -f 3)
EXPECTED_RESULT=0x515dcadf

if [ $RESULT != $EXPECTED_RESULT ];
then
    echo "ID generator broken $RESULT != $EXPECTED_RESULT"
    exit 1
fi
