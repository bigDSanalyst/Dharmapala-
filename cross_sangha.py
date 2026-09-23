
import hashlib
from dataclasses import dataclass, replace
from compression import merkle_root

@dataclass(frozen=True)
class CrossSanghaAttestation:
    sangha_id: str; class_id: str; count: int
    witness_hashes: tuple; witness_merkle_root: str
    nullifier_root: str; epoch: int; signature: str = ""
    def payload(self):
        wh = "~".join(self.witness_hashes)
        return (f"{self.sangha_id}|{self.class_id}|{self.count}|"
                f"{wh}|{self.witness_merkle_root}|{self.nullifier_root}|"
                f"{self.epoch}").encode()

class GlobalNullifierSet:
    def __init__(self): self._seen = set()
    def is_new(self, n): return n not in self._seen
    def absorb(self, ns):
        for n in ns: self._seen.add(n)

def nullifier_for(witness_hash, sangha_id):
    return hashlib.sha256(f"{witness_hash}|{sangha_id}".encode()).hexdigest()

def publish(ledger, sangha_id, class_id, signer, epoch):
    witnesses = [r for r in ledger.records
                 if r.class_id == class_id
                 and r.verdict_kind in ("LAWFUL", "LEARNING")]
    if not witnesses: return None
    wh = [r.hash() for r in witnesses]
    nf = [nullifier_for(h, sangha_id) for h in wh]
    a = CrossSanghaAttestation(sangha_id=sangha_id, class_id=class_id,
                               count=len(witnesses), witness_hashes=tuple(wh),
                               witness_merkle_root=merkle_root(wh),
                               nullifier_root=merkle_root(nf), epoch=epoch)
    sig = signer.sign(a.payload())
    return replace(a, signature=sig.hex())

def verify(a, verifier, nullifier_set):
    if not a.signature: return False, "missing signature"
    try: sig_bytes = bytes.fromhex(a.signature)
    except ValueError: return False, "signature not hex"
    if not verifier.verify(a.payload(), sig_bytes): return False, "signature invalid"
    if merkle_root(list(a.witness_hashes)) != a.witness_merkle_root:
        return False, "witness_hashes do not match witness_merkle_root"
    if len(a.witness_hashes) != a.count:
        return False, "count does not match witness_hashes length"
    return True, "ok"

def aggregate(attestations, verifier, nullifier_set):
    credit = {}; signers = {}; rejected = 0
    for a in attestations:
        ok, _ = verify(a, verifier, nullifier_set)
        if not ok: rejected += 1; continue
        for w in a.witness_hashes:
            credit[w] = 1
            signers.setdefault(w, set()).add(a.sangha_id)
    return {"credit": credit, "signers": signers,
            "n_unique": len(credit), "n_rejected": rejected}
