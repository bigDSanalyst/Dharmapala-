
import hashlib, secrets

class GuardNonce:
    def __init__(self): self._r = None; self.commitment = None
    def commit(self):
        self._r = secrets.token_bytes(32)
        self.commitment = hashlib.sha256(self._r).hexdigest()
        return self.commitment
    def reveal(self):
        if self._r is None: raise RuntimeError("no pending nonce")
        if hashlib.sha256(self._r).hexdigest() != self.commitment:
            raise RuntimeError("commitment mismatch")
        return self._r

def public_beacon(epoch):
    return hashlib.sha256(f"public-beacon-epoch-{epoch}".encode()).digest()

def selection_seed(epoch, guard_nonce_bytes):
    return hashlib.sha256(public_beacon(epoch) + guard_nonce_bytes +
                          epoch.to_bytes(8, "big")).digest()

def unbias(seed, n):
    while True:
        k = int.from_bytes(seed[:8], "big")
        limit = (2**64 // n) * n
        if k < limit: return k % n
        seed = hashlib.sha256(seed).digest()
