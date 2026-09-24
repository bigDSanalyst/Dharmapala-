
import hashlib, secrets

# Selection randomness the guard cannot grind. The old public beacon was
# sha256 of a fixed string, known for every future epoch, so a guard could
# try nonces offline and commit to one that selected an easy class. Now the
# order is enforced: the guard commits, a counterparty contributes randomness
# chosen after seeing the commitment, and only then does the guard reveal.
# At commit time the guard does not know the contribution, so it has nothing
# to grind against. A guard that withholds its reveal has refused the epoch.
# In deployment the contribution should come from a public source published
# after the commitment (a drand round, or a Bitcoin block hash).

class GuardNonce:
    def __init__(self, epoch):
        self.epoch = epoch; self._r = None
        self.commitment = None; self.contribution = None
    def commit(self):
        if self.commitment is not None: raise RuntimeError("already committed")
        self._r = secrets.token_bytes(32)
        self.commitment = hashlib.sha256(self._r).hexdigest()
        return self.commitment
    def receive(self, contribution):
        if self.commitment is None: raise RuntimeError("contribution before commitment")
        if self.contribution is not None: raise RuntimeError("contribution already received")
        self.contribution = contribution
    def reveal(self):
        if self.contribution is None: raise RuntimeError("reveal before contribution")
        return self._r
    def seed(self):
        return selection_seed(self.epoch, self.commitment, self.contribution, self.reveal())

class Counterparty:
    def __init__(self): self.seen = {}
    def contribute(self, epoch, commitment):
        if not commitment: raise ValueError("no commitment to respond to")
        if epoch in self.seen: raise RuntimeError(f"epoch {epoch} already contributed")
        c = secrets.token_bytes(32); self.seen[epoch] = (commitment, c)
        return c

def selection_seed(epoch, commitment, contribution, nonce):
    if hashlib.sha256(nonce).hexdigest() != commitment:
        raise ValueError("nonce does not open the commitment")
    return hashlib.sha256(b"dharmapala/selection/v2|" + epoch.to_bytes(8, "big") +
                          bytes.fromhex(commitment) + contribution + nonce).digest()

def unbias(seed, n):
    while True:
        k = int.from_bytes(seed[:8], "big")
        limit = (2**64 // n) * n
        if k < limit: return k % n
        seed = hashlib.sha256(seed).digest()
