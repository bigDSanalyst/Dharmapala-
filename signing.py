
import hashlib, hmac, secrets

class HMACSigner:
    scheme = "hmac-sha256"; publicly_verifiable = False
    def __init__(self, signer_id, key):
        self.id = signer_id; self._key = key
    def sign(self, payload):
        return hmac.new(self._key, payload, hashlib.sha256).digest()
    def verify(self, payload, signature):
        return hmac.compare_digest(
            hmac.new(self._key, payload, hashlib.sha256).digest(), signature)
    def public_bytes(self):
        raise TypeError("hmac-sha256 has no public key: whoever can verify can also sign")

class MLDSASigner:
    scheme = "ml-dsa-65"; publicly_verifiable = True
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
    publicly_verifiable = True
    def __init__(self, signer_id, scheme, public_bytes):
        if scheme != "ml-dsa-65":
            raise ValueError(f"{scheme} has no public verifier")
        self.id = signer_id; self.scheme = scheme; self._pub = public_bytes
    def verify(self, payload, signature):
        try:
            from dilithium_py.ml_dsa import ML_DSA_65
            return ML_DSA_65.verify(self._pub, payload, signature)
        except Exception: return False
    def key_id(self): return hashlib.sha256(self._pub).hexdigest()

class SharedSecretVerifier:
    # Checks HMAC signatures by holding the signing key, so it can also forge
    # them: an HMAC signature shows only that some holder of the key made it.
    scheme = "hmac-sha256"; publicly_verifiable = False
    def __init__(self, signer):
        self.id = signer.id; self._signer = signer
    def verify(self, payload, signature): return self._signer.verify(payload, signature)
    def key_id(self): return hashlib.sha256(b"hmac|" + self._signer._key).hexdigest()

def default_signer(signer_id):
    # ML-DSA-65 when dilithium-py is installed. Otherwise HMAC under a fresh
    # key per signer, so two signers never share one. The fallback shows as
    # .scheme, and doctor reports every shared-secret verifier as DEGRADED.
    try:
        import dilithium_py.ml_dsa
        return MLDSASigner.generate(signer_id)
    except ImportError:
        return HMACSigner(signer_id, secrets.token_bytes(32))

def verifier_for(signer):
    if signer.publicly_verifiable:
        return PublicVerifier(signer.id, signer.scheme, signer.public_bytes())
    return SharedSecretVerifier(signer)

def public_verifier_for(signer):
    return PublicVerifier(signer.id, signer.scheme, signer.public_bytes())
