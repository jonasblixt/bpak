import _bpak
import hashlib

HAVE_CRYPTO = False
try:
    from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p, NIST521p
    from ecdsa.util import sigdecode_der
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

class Package(_bpak.Package):
    def __init__(self, filename, mode):
        self.pkg = _bpak.Package(filename, mode)
    def id(self):
        return self.pkg.id()
    def set_key_id(self, key_id, keystore_id):
        pass
    def sign(self, signing_key_path):
        if not HAVE_CRYPTO:
            raise Exception("ecdsa library not installed")
        return True
    def verify(self, verify_key_path):
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
