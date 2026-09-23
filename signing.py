
import hashlib, hmac

class HMACSigner:
    scheme = "hmac-sha256"
    def __init__(self, signer_id, key):
        self.id = signer_id; self._key = key
    def sign(self, payload):
        return hmac.new(self._key, payload, hashlib.sha256).digest()
    def verify(self, payload, signature):
        return hmac.compare_digest(
            hmac.new(self._key, payload, hashlib.sha256).digest(), signature)
    def public_bytes(self): return self._key

class MLDSASigner:
    scheme = "ml-dsa-65"
    def __init__(self, signer_id, pk, sk):
        self.id = signer_id; self._pk = pk; self._sk = sk
    @classmethod
    def generate(cls, signer_id):
        from dilithium_py.ml_dsa import ML_DSA_65
        pk, sk = ML_DSA_65.keygen()
        return cls(signer_id, pk, sk)
    def sign(self, payload):
        from dilithium_py.ml_dsa import ML_DSA_65
        return ML_DSA_65.sign(self._sk, payload)
    def verify(self, payload, signature):
        from dilithium_py.ml_dsa import ML_DSA_65
        try: return ML_DSA_65.verify(self._pk, payload, signature)
        except Exception: return False
    def public_bytes(self): return self._pk

class PublicVerifier:
    def __init__(self, signer_id, scheme, public_bytes):
        self.id = signer_id; self.scheme = scheme; self._pub = public_bytes
    def verify(self, payload, signature):
        if self.scheme == "ml-dsa-65":
            try:
                from dilithium_py.ml_dsa import ML_DSA_65
                return ML_DSA_65.verify(self._pub, payload, signature)
            except Exception: return False
        if self.scheme == "hmac-sha256":
            return hmac.compare_digest(
                hmac.new(self._pub, payload, hashlib.sha256).digest(), signature)
        raise ValueError(f"unknown scheme: {self.scheme}")

def default_signer(signer_id, fallback_key):
    try:
        import dilithium_py.ml_dsa
        return MLDSASigner.generate(signer_id)
    except ImportError:
        return HMACSigner(signer_id, fallback_key)

def public_verifier_for(signer):
    return PublicVerifier(signer.id, signer.scheme, signer.public_bytes())
