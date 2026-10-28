"""Verification must detect corruption anywhere in a signed package"""

import pytest

from bpaktest import (DEFAULT_VERIFY_KEY, HEADER_SIZE, BpakError, Part,
                      corrupt)

DATA_SIZE_KIB = 128


@pytest.mark.parametrize("part, offset, error", [
    # Corruption of the meta data array in the header
    pytest.param(None, 8, BpakError.VERIFY_FAIL, id="header"),
    # Corruption in a part that is covered by the payload hash
    pytest.param("plain", HEADER_SIZE, BpakError.BAD_PAYLOAD_HASH,
                 id="payload"),
    # The merkle tree is rebuilt from the data, so the root hash in the
    # signed header will not match
    pytest.param("merkle", HEADER_SIZE, BpakError.VERIFY_FAIL,
                 id="payload-with-merkle-tree"),
    # The merkle tree is located directly after the part data
    pytest.param("merkle", HEADER_SIZE + DATA_SIZE_KIB * 1024,
                 BpakError.VERIFY_FAIL, id="merkle-tree"),
])
def test_corruption_is_detected(bpak, make_data, part, offset, error):
    parts = []
    if part is not None:
        data = make_data("data.bin", DATA_SIZE_KIB)
        parts.append(Part("fs", data, merkle=(part == "merkle")))

    pkg = bpak.create_package("test.bpak", parts=parts)
    bpak("verify", pkg, "--key", DEFAULT_VERIFY_KEY)

    corrupt(pkg, offset)

    bpak.fails("verify", pkg, "--key", DEFAULT_VERIFY_KEY, error=error)


def test_truncated_package(bpak, make_data):
    data = make_data("data.bin", DATA_SIZE_KIB)
    pkg = bpak.create_package("test.bpak", parts=[Part("fs", data)])

    with open(pkg, "r+b") as f:
        f.truncate(HEADER_SIZE + DATA_SIZE_KIB * 1024 - 1)

    bpak.fails("verify", pkg, "--key", DEFAULT_VERIFY_KEY,
               error=BpakError.READ_ERROR)
