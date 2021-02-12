import _bpak
import hashlib

BPAK_HASH_INVALID = 0
BPAK_HASH_SHA256 = 1
BPAK_HASH_SHA384 = 2
BPAK_HASH_SHA512 = 3

HAVE_CRYPTO = False
try:
    from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p, NIST521p
    from ecdsa.util import sigdecode_der, sigencode_der
    HAVE_CRYPTO = True
except:
    pass

def id(input_string):
    """Converts a text string to a BPAK ID"""
    return _bpak.id(input_string)

def set_log_function(log_func):
    """Set a logging call back. The log function should have two arguments:
        my_log_func(level, message)"""
    _bpak.set_log_func(log_func)

class Package:
    def __init__(self, filename, mode):
        self.pkg = _bpak.Package(filename, mode)
    def close(self):
        self.pkg.close()
    def id(self):
        return self.pkg.id()
    def set_key_id(self, key_id):
        return self.pkg.set_key_id(id(key_id))
    def set_keystore_id(self, keystore_id):
        return self.pkg.set_keystore_id(id(keystore_id))
    def sign(self, signing_key_path):
        """Sign a package using a DER or PEM encoded private key"""
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

        if hash_kind == BPAK_HASH_SHA256:
            sha_func = hashlib.sha256
        elif hash_kind == BPAK_HASH_SHA384:
            sha_func = hashlib.sha384
        elif hash_kind == BPAK_HASH_SHA512:
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
