
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

def verify(a, verifiers):
    # verifiers maps each sangha_id to that sangha's own verifier. The id in
    # the attestation is a claim; only the key registered for it can back it.
    verifier = verifiers.get(a.sangha_id)
    if verifier is None: return False, f"no verifier registered for sangha {a.sangha_id!r}"
    if verifier.id != a.sangha_id:
        return False, f"verifier {verifier.id!r} registered under sangha {a.sangha_id!r}"
    if not a.signature: return False, "missing signature"
    try: sig_bytes = bytes.fromhex(a.signature)
    except ValueError: return False, "signature not hex"
    if not verifier.verify(a.payload(), sig_bytes): return False, "signature invalid"
    if merkle_root(list(a.witness_hashes)) != a.witness_merkle_root:
        return False, "witness_hashes do not match witness_merkle_root"
    if merkle_root([nullifier_for(h, a.sangha_id) for h in a.witness_hashes]) != a.nullifier_root:
        return False, "nullifier_root does not match witness_hashes"
    if len(a.witness_hashes) != a.count:
        return False, "count does not match witness_hashes length"
    return True, "ok"

def distinct_keys(verifiers):
    # One key standing behind two sangha ids is one witness counted twice.
    seen = {}
    for sid, v in verifiers.items():
        k = v.key_id()
        if k in seen: return False, f"sanghas {seen[k]!r} and {sid!r} share one key"
        seen[k] = sid
    return True, "ok"

def aggregate(attestations, verifiers, nullifier_set=None):
    ok, why = distinct_keys(verifiers)
    if not ok: raise ValueError(why)
    credit = {}; signers = {}; rejected = 0; replayed = 0
    for a in attestations:
        ok, _ = verify(a, verifiers)
        if not ok: rejected += 1; continue
        nfs = [nullifier_for(w, a.sangha_id) for w in a.witness_hashes]
        if nullifier_set is not None and not all(nullifier_set.is_new(n) for n in nfs):
            replayed += 1; continue
        for w in a.witness_hashes:
            credit[w] = 1
            signers.setdefault(w, set()).add(a.sangha_id)
        if nullifier_set is not None: nullifier_set.absorb(nfs)
    return {"credit": credit, "signers": signers,
            "n_unique": len(credit), "n_rejected": rejected, "n_replayed": replayed}
