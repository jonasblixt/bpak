#!/bin/sh
BPAK=../src/bpak
echo Test help output
set -e

$BPAK --help
$BPAK create --help
$BPAK add --help
$BPAK transport --help
$BPAK sign --help
$BPAK verify --help
$BPAK show --help
$BPAK set --help
$BPAK generate --help
$BPAK compare --help

