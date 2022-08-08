try:
    # It's not possible to include the C extension when building
    #  readthedocs.io documentation. And it's not needed for generating
    # the documentation.
    import _bpak
except:
    print("Warning: Could not import bpak C extension")

import hashlib
import uuid
import semver
from bpak.utils import id
import bpak

HAVE_CRYPTO = False
try:
    from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p, NIST521p
    from ecdsa.util import sigdecode_der, sigencode_der
    HAVE_CRYPTO = True
except:
    pass

class Package:
    """
    BPAK Python wrapper

    This class wraps the high level BPAK API
    """
    def __init__(self, filename, mode):
        self.pkg = _bpak.Package(filename, mode)
    def close(self):
        """
        Close BPAK archive
        """
        self.pkg.close()
    def id(self):
        """
        Return the bpak-package UUID metadata
        """
        raw_pkg_id = self.pkg.read_raw_meta(id("bpak-package"), 0)
        return uuid.UUID(bytes=raw_pkg_id)
    def version(self):
        """
        Read 'bpak-version' metadata
        """
        return self.read_string_meta(id("bpak-version"), 0)
    def read_string_meta(self, meta_id, part_ref_id=0):
        """
        Read a string metadata
        """
        raw_data = self.read_raw_meta(meta_id, part_ref_id)
        return raw_data[:-1].decode('utf-8')
    def read_hex_meta(self, meta_id, part_ref_id=0):
        """
        Read metadata and return result as a hex-string
        """
        raw_data = self.read_raw_meta(meta_id, part_ref_id)
        return raw_data.hex()
    def write_string_meta(self, meta_id, input_string, part_ref_id=0):
        """
        Write string meta data
        """
        raw_data = bytes(input_string, 'utf-8') + b'\x00'
        return self.pkg.write_raw_meta(meta_id, part_ref_id, raw_data)
    def read_raw_meta(self, meta_id, part_ref_id=0):
        """
        Read raw meta data. The result is a byte string
        """
        return self.pkg.read_raw_meta(meta_id, part_ref_id)
    def write_raw_meta(self, meta_id, meta_data, part_ref_id=0):
        """
        Write raw meta data. The input should be a byte string
        """
        return self.pkg.write_raw_meta(meta_id, part_ref_id, meta_data)
    def transport(self, origin, output):
        """
        Transport encode package
        """
        return self.pkg.transport(origin.pkg, output.pkg)
    def deps(self):
        """
        Read package dependencies
        """
        # return self.pkg.deps()
        raise Exception("Broken, don't use this for the moment")
    def size(self):
        """
        Return the size of the package in bytes.
        """
        return self.pkg.size()
    def installed_size(self):
        """
        Return the installed size of the package in bytes.

        Calling this on a transport encoded package will give the size required
        in bytes after the package has been transport decoded.
        """
        return self.pkg.installed_size()
    def set_hash_kind(self, hash_kind):
        """
        Set the hash algorithm that should be used for this package.
        """
        return self.pkg.set_hash_kind(hash_kind)
    def set_signature_kind(self, sign_kind):
        """
        Set the signature kind that should be used for this package.
        """
        return self.pkg.set_sign_kind(sign_kind)
    def set_key_id(self, key_id):
        """
        Set the key-id hint. This is used to select the correct public key when verifying the package.
        """
        return self.pkg.set_key_id(key_id)
    def set_keystore_id(self, keystore_id):
        """
        Set the keystore-id hint. When verifying the package the package key-id key is expected to exist in a keystore with id 'keystore_id'
        """
        return self.pkg.set_keystore_id(keystore_id)
    def sign(self, signing_key_path):
        """
        Sign a package using a DER or PEM encoded private key
        """
        if not HAVE_CRYPTO:
            raise Exception("ecdsa library not installed")

        raw_key_data = ""
        with open(signing_key_path, "rb") as f:
            raw_key_data = f.read()

        sk = None
        try:
            sk = SigningKey.from_der(raw_key_data)
        except:
            pass

        try:
            sk = SigningKey.from_pem(raw_key_data)
        except:
            pass

        if sk is None:
            raise Exception("Could not load private key")

        digest = self.pkg.read_digest()
        hash_kind = self.pkg.read_hash_kind()
        sha_func = None

        if hash_kind == bpak.BPAK_HASH_SHA256:
            sha_func = hashlib.sha256
        elif hash_kind == bpak.BPAK_HASH_SHA384:
            sha_func = hashlib.sha384
        elif hash_kind == bpak.BPAK_HASH_SHA512:
            sha_func = hashlib.sha512
        else:
            raise Exception("Unknown hash kind %i"%(hash_kind))

        sig = sk.sign_digest_deterministic(digest, sha_func,
                                            sigencode=sigencode_der)
        self.pkg.set_signature(sig)
        return True
    def verify(self, verify_key_path):
        """Verify the package using a DER or PEM encoded public key"""
        if not HAVE_CRYPTO:
            raise Exception("ecdsa library not installed")

        raw_key_data = ""
        with open(verify_key_path, "rb") as f:
            raw_key_data = f.read()

        vk = None
        try:
            vk = VerifyingKey.from_der(raw_key_data)
        except:
            pass

        try:
            vk = VerifyingKey.from_pem(raw_key_data)
        except:
            pass

        if vk is None:
            raise Exception("Could not load public key")

        sig = self.pkg.read_signature()
        digest = self.pkg.read_digest()

        return vk.verify_digest(sig, digest, sigdecode=sigdecode_der)
    def __str__(self):
        return "<BPAK %s>"%(self.id())
