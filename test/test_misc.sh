#!/bin/sh
BPAK=../src/bpak

set -e

$BPAK
$BPAK -V
$BPAK -h

IMG=test_misc.bpak
V=-vvv

$BPAK create $IMG -Y $V
$BPAK add $IMG --meta test-string --from-string hello $V
$BPAK add $IMG --meta test-int --from-string 0x12345678 --encoder integer $V

set
