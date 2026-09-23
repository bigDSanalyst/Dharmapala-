
import hashlib, hmac
from dataclasses import dataclass, replace

GENESIS_HASH = "0" * 64

@dataclass(frozen=True)
class CompressionEntry:
    kind: str; through_index: int; root: str; bridge_prev_hash: str
    epoch: int; signer_id: str; signature: str = ""
    def payload(self):
        return (f"{self.kind}|{self.through_index}|{self.root}|"
                f"{self.bridge_prev_hash}|{self.epoch}|{self.signer_id}").encode()
    def hash(self): return hashlib.sha256(self.payload()).hexdigest()

def merkle_root(hashes):
    if not hashes: return GENESIS_HASH
    layer = list(hashes)
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer) - 1, 2):
            nxt.append(hashlib.sha256((layer[i] + layer[i+1]).encode()).hexdigest())
        if len(layer) % 2: nxt.append(layer[-1])
        layer = nxt
    return layer[0]
