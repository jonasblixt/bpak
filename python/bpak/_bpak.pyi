from collections.abc import Callable
from types import TracebackType
from typing import Final, Self

FLAG_EXCLUDE_FROM_HASH: Final[int]
FLAG_TRANSPORT: Final[int]

HASH_SHA256: Final[int]
HASH_SHA384: Final[int]
HASH_SHA512: Final[int]

KEY_PUB_PRIME256v1: Final[int]
KEY_PUB_RSA4096: Final[int]
KEY_PUB_SECP384r1: Final[int]
KEY_PUB_SECP521r1: Final[int]

SIGN_PRIME256v1: Final[int]
SIGN_RSA4096: Final[int]
SIGN_SECP384r1: Final[int]
SIGN_SECP521r1: Final[int]

class Error(Exception): ...

class Meta:
    id: int
    part_id_ref: int
    size: int
    raw_data: bytes

    def as_uuid(self) -> object: ...
    def as_string(self) -> str: ...
    def delete(self) -> None: ...

class Part:
    id: int
    size: int
    offset: int
    is_transport_encoded: bool
    flags: int
    transport_size: int
    pad_bytes: int

    def read_data(self) -> bytes: ...
    def delete(self, keep_meta: bool = False) -> None: ...

class Package:
    digest: bytes
    hash_kind: int
    signature_kind: int
    key_id: int
    keystore_id: int
    signature: bytes
    size: int
    installed_size: int
    parts: list[Part]
    meta: list[Meta]

    def __init__(self, filename: str, mode: str = "rb") -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
    def close(self) -> None: ...
    def verify(self, verify_key_path: str) -> bool: ...
    def sign(self, sign_key_path: str) -> bool: ...
    def verify_with_keystore(self, keystore_path: str) -> bool: ...
    def add_file(
        self,
        part_name: str,
        filename: str,
        with_merkle_tree: bool = False,
        flags: int = 0,
    ) -> Part: ...
    def add_key(self, part_name: str, filename: str, flags: int = 0) -> Part: ...
    def add_meta(
        self,
        id: int,
        part_id_ref: int = 0,
        data: bytes | str | None = None,
        size: int = -1,
    ) -> Meta: ...
    def get_part(self, id: int) -> Part: ...
    def get_meta(self, id: int, part_id_ref: int = 0) -> Meta: ...
    def extract_file(self, part_id: int, filename: str) -> None: ...
    def delete_all_parts(self, keep_meta: bool = False) -> None: ...
    def part_sha256(self, part_id: int) -> bytes: ...

def id(string: str) -> int: ...
def set_log_func(log_func: Callable[[int, str], None] | None) -> None: ...
def transport_encode(
    input: Package,
    output: Package,
    origin: Package | None = None,
) -> None: ...
def transport_decode(
    input: Package,
    output: Package,
    origin: Package | None = None,
) -> None: ...
def hash_kind_str(kind: int) -> str: ...
def signature_kind_str(kind: int) -> str: ...
def id_to_string(id: int) -> str | None: ...
def meta_to_string(package: Package, meta: Meta) -> str | None: ...
def add_transport_meta(
    package: Package,
    part_id: int,
    encoder_id: int,
    decoder_id: int,
) -> None: ...
def parse_public_key(data: bytes) -> tuple[int, bytes]: ...
