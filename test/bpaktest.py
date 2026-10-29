"""Helpers shared by the bpak tool and python package tests."""

import enum
import os
import random
import shlex
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
SOURCE_DIR = Path(__file__).parent.parent

PKG_UUID = "0888b0fa-9c48-4524-9845-06a641b61edd"
DEFAULT_SIGN_KEY = DATA_DIR / "secp256r1-key-pair.pem"
DEFAULT_VERIFY_KEY = DATA_DIR / "secp256r1-pub-key.der"

# A keystore created by a released version, see the keystore fixture
GOLDEN_KEYSTORE = SOURCE_DIR / "test" / "golden" / "0.9.3" / "keystore.bpak"


class BpakError(enum.IntEnum):
    """'enum bpak_errors' in include/bpak/bpak.h"""

    FAILED = 1
    NOT_FOUND = 2
    SIZE_ERROR = 3
    NO_SPACE_LEFT = 4
    BAD_ALIGNMENT = 5
    SEEK_ERROR = 6
    NOT_SUPPORTED = 7
    NEEDS_MORE_DATA = 8
    WRITE_ERROR = 9
    DECOMPRESSOR_ERROR = 10
    COMPRESSOR_ERROR = 11
    PATCH_READ_ORIGIN_ERROR = 12
    PATCH_WRITE_ERROR = 13
    READ_ERROR = 14
    BAD_MAGIC = 15
    UNSUPPORTED_HASH_ALG = 16
    BUFFER_TOO_SMALL = 17
    FILE_NOT_FOUND = 18
    KEY_DECODE = 19
    VERIFY_FAIL = 20
    SIGN_FAIL = 21
    UNSUPPORTED_KEY = 22
    BAD_ROOT_HASH = 23
    BAD_PAYLOAD_HASH = 24
    MISSING_META_DATA = 25
    PACKAGE_UUID_MISMATCH = 26
    UNSUPPORTED_COMPRESSION = 27
    KEY_NOT_FOUND = 28
    KEYSTORE_ID_MISMATCH = 29
    EXISTS = 30

    @property
    def exit_code(self) -> int:
        """The tool exits with the negated error code"""
        return -self & 0xFF


@dataclass(frozen=True)
class Part:
    """A part to add to a package.

    'source' may contain a '{}' placeholder that is replaced with the
    package version, see Part.for_version.
    """

    name: str
    source: Path
    # Exclude the part from the payload hash
    dont_hash: bool = False
    # Append a merkle hash tree. Implies dont_hash, the integrity of the data
    # is then covered by the merkle root hash in the header instead.
    merkle: bool = False

    def for_version(self, version: str) -> "Part":
        return Part(self.name,
                    Path(str(self.source).format(version)),
                    self.dont_hash,
                    self.merkle)


@dataclass(frozen=True)
class Transport:
    """A transport encoding rule for a part"""

    part: str
    encoder: str
    decoder: str


def random_bytes(size: int, seed: int = 0) -> bytes:
    """Pseudo-random data that is the same in every run"""
    return random.Random(seed).randbytes(size)


def python_path(build_dir: Path) -> list:
    """The python path of the bpak package in a CMake build directory"""
    return [str(build_dir / "tools")]


class Bpak:
    """Runs the bpak tool, 'python -m bpak', with 'cwd' as working directory.

    'path' is put first on the python path, see python_path(), an empty path
    runs the installed package.

    The command line and its output is printed so that pytest shows a full
    transcript for failing tests.
    """

    def __init__(self, path: list, cwd: Path):
        self.cwd = cwd
        self.env = dict(os.environ)
        if path:
            self.env["PYTHONPATH"] = os.pathsep.join(
                [*path, *filter(None, [os.environ.get("PYTHONPATH")])])

    def run(self, *args, check: bool = True,
            verbose: bool = True) -> subprocess.CompletedProcess:
        cmd = [str(arg) for arg in args]
        if verbose:
            cmd.append("-vvv")

        result = subprocess.run([sys.executable, "-m", "bpak", *cmd],
                                cwd=self.cwd, env=self.env,
                                capture_output=True)

        print(f"$ bpak {shlex.join(cmd)}")
        print(result.stdout.decode(errors="replace"), end="")
        print(result.stderr.decode(errors="replace"), end="")

        if check and result.returncode != 0:
            raise AssertionError(
                f"'bpak {shlex.join(cmd)}' exited with {result.returncode}")
        return result

    __call__ = run

    def output(self, *args) -> bytes:
        """Run without verbose logging and return stdout"""
        return self.run(*args, verbose=False).stdout

    def fails(self, *args, error: BpakError) -> None:
        """Run and expect the command to fail with 'error'"""
        result = self.run(*args, check=False)
        assert result.returncode == error.exit_code, (
            f"expected {error.name} (exit code {error.exit_code}), "
            f"got exit code {result.returncode}")

    def create_package(self, path, *, parts=(), transport=(),
                       hash_kind=None, signature_kind=None,
                       sign_key=DEFAULT_SIGN_KEY, package_uuid=PKG_UUID,
                       key_id="pb-development",
                       keystore_id="pb-internal") -> Path:
        """Create a package the way most tests need it.

        Sets the package UUID, adds transport rules and parts, sets key-id
        and keystore-id and signs the package with 'sign_key' unless it is
        None.
        """
        create_args = []
        if hash_kind:
            create_args += ["--hash-kind", hash_kind]
        if signature_kind:
            create_args += ["--signature-kind", signature_kind]

        self("create", path, "-Y", *create_args)
        self("add", path, "--meta", "bpak-package",
             "--from-string", package_uuid, "--encoder", "uuid")

        for rule in transport:
            self("transport", path, "--add", "--part", rule.part,
                 "--encoder", rule.encoder, "--decoder", rule.decoder)

        for part in parts:
            args = ["--part", part.name, "--from-file", part.source]
            if part.dont_hash or part.merkle:
                args += ["--set-flag", "dont-hash"]
            if part.merkle:
                args += ["--encoder", "merkle"]
            self("add", path, *args)

        self("set", path, "--key-id", key_id, "--keystore-id", keystore_id)

        if sign_key is not None:
            self("sign", path, "--key", sign_key)

        return self.cwd / path


def corrupt(path: Path, offset: int, length: int = 16) -> None:
    """Overwrite 'length' bytes at 'offset' with zeros"""
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(bytes(length))


def bpak_id(name: str, crc: int = 0) -> int:
    """bpak_id() in lib/id.c, a CRC32 without the initial and final XOR"""
    return zlib.crc32(name.encode(), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def hash_tree_id(part_name: str) -> int:
    """Id of the merkle hash tree part that belongs to 'part_name'"""
    return bpak_id("-hash-tree", bpak_id(part_name))


# Layout of 'struct bpak_header' in include/bpak/bpak.h. This is the on-disk
# format, it must never change.
HEADER_SIZE = 4096
MAX_META = 32
MAX_PARTS = 32
META_OFFSET = 8
META_SIZE = 16
PARTS_OFFSET = META_OFFSET + MAX_META * META_SIZE
PART_SIZE = 32
METADATA_OFFSET = PARTS_OFFSET + MAX_PARTS * PART_SIZE
METADATA_SIZE = 1920
HASH_KIND_OFFSET = METADATA_OFFSET + METADATA_SIZE
SIGNATURE_KIND_OFFSET = HASH_KIND_OFFSET + 1
ALIGNMENT_OFFSET = SIGNATURE_KIND_OFFSET + 1
PAYLOAD_HASH_OFFSET = ALIGNMENT_OFFSET + 2
KEY_ID_OFFSET = PAYLOAD_HASH_OFFSET + 64
KEYSTORE_ID_OFFSET = KEY_ID_OFFSET + 4
SIGNATURE_OFFSET = KEYSTORE_ID_OFFSET + 4 + 42
SIGNATURE_SIZE = 512
SIGNATURE_SZ_OFFSET = SIGNATURE_OFFSET + SIGNATURE_SIZE
assert SIGNATURE_SZ_OFFSET + 2 == HEADER_SIZE

FLAG_EXCLUDE_FROM_HASH = 1 << 0
FLAG_TRANSPORT = 1 << 1


@dataclass(frozen=True)
class MetaHeader:
    id: int
    size: int
    offset: int
    part_id_ref: int


@dataclass(frozen=True)
class PartHeader:
    id: int
    size: int
    offset: int
    transport_size: int
    pad_bytes: int
    flags: int

    @property
    def stored_size(self) -> int:
        """Size of the part in the file, bpak_part_size()"""
        if self.flags & FLAG_TRANSPORT:
            return self.transport_size
        return self.size + self.pad_bytes


class Header:
    """Parses 'struct bpak_header' from the start of a package"""

    def __init__(self, data: bytes):
        data = data[:HEADER_SIZE]
        self.raw = data
        self.magic, = struct.unpack_from("<I", data, 0)

        self.meta = []
        for i in range(MAX_META):
            meta = MetaHeader(*struct.unpack_from(
                "<IHHI", data, META_OFFSET + i * META_SIZE))
            if meta.id:
                self.meta.append(meta)

        self.parts = []
        for i in range(MAX_PARTS):
            part = PartHeader(*struct.unpack_from(
                "<IQQQHB", data, PARTS_OFFSET + i * PART_SIZE))
            if part.id:
                self.parts.append(part)

        (self.hash_kind, self.signature_kind,
         self.alignment) = struct.unpack_from("<BBH", data, HASH_KIND_OFFSET)
        self.payload_hash = data[PAYLOAD_HASH_OFFSET:KEY_ID_OFFSET]
        self.key_id, self.keystore_id = struct.unpack_from(
            "<II", data, KEY_ID_OFFSET)
        self.signature_sz, = struct.unpack_from("<H", data,
                                                SIGNATURE_SZ_OFFSET)
        self.signature = data[SIGNATURE_OFFSET:
                              SIGNATURE_OFFSET + self.signature_sz]

    @classmethod
    def read(cls, path: Path) -> "Header":
        with open(path, "rb") as f:
            return cls(f.read(HEADER_SIZE))

    def meta_data(self, id: int, part_id_ref: int = 0) -> bytes:
        for meta in self.meta:
            if meta.id == id and meta.part_id_ref == part_id_ref:
                start = METADATA_OFFSET + meta.offset
                return self.raw[start:start + meta.size]
        raise KeyError(f"meta {id:#x}/{part_id_ref:#x} not found")

    def part(self, id: int) -> PartHeader:
        for part in self.parts:
            if part.id == id:
                return part
        raise KeyError(f"part {id:#x} not found")

    def part_offset(self, id: int) -> int:
        """Offset of the part data in the file, bpak_part_offset()"""
        offset = HEADER_SIZE
        for part in self.parts:
            if part.id == id:
                return offset
            offset += part.stored_size
        raise KeyError(f"part {id:#x} not found")
