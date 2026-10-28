"""Helpers shared by the bpak tool and python wrapper tests."""

import enum
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
SOURCE_DIR = Path(__file__).parent.parent

PKG_UUID = "0888b0fa-9c48-4524-9845-06a641b61edd"
DEFAULT_SIGN_KEY = DATA_DIR / "secp256r1-key-pair.pem"
DEFAULT_VERIFY_KEY = DATA_DIR / "secp256r1-pub-key.der"


class BpakError(enum.IntEnum):
    """Subset of 'enum bpak_errors' in include/bpak/bpak.h"""

    VERIFY_FAIL = 20
    BAD_PAYLOAD_HASH = 24

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


class Bpak:
    """Runs the bpak tool with 'cwd' as working directory.

    The command line and its output is printed so that pytest shows a full
    transcript for failing tests.
    """

    def __init__(self, tool: Path, cwd: Path):
        self.tool = tool
        self.cwd = cwd

    def run(self, *args, check: bool = True,
            verbose: bool = True) -> subprocess.CompletedProcess:
        cmd = [str(self.tool), *(str(arg) for arg in args)]
        if verbose:
            cmd.append("-vvv")

        result = subprocess.run(cmd, cwd=self.cwd, capture_output=True)

        print(f"$ {shlex.join(cmd)}")
        print(result.stdout.decode(errors="replace"), end="")
        print(result.stderr.decode(errors="replace"), end="")

        if check and result.returncode != 0:
            raise AssertionError(
                f"'{shlex.join(cmd)}' exited with {result.returncode}")
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
                       sign_key=DEFAULT_SIGN_KEY) -> Path:
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
             "--from-string", PKG_UUID, "--encoder", "uuid")

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

        self("set", path, "--key-id", "pb-development",
             "--keystore-id", "pb-internal")

        if sign_key is not None:
            self("sign", path, "--key", sign_key)

        return self.cwd / path


def corrupt(path: Path, offset: int, length: int = 16) -> None:
    """Overwrite 'length' bytes at 'offset' with zeros"""
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(bytes(length))
