
import hashlib, math
import merkle
from dataclasses import dataclass, replace
from typing import Callable, Optional

STRATEGY_SPEC = "highest-pressure-unproven-v1"
GENESIS_HASH = "0" * 64
@dataclass(frozen=True)
class Class:
    id: str; source_clause: str; pressure: float = 0.0

@dataclass(frozen=True)
class AdversaryCommitment:
    epoch: int; class_index_root: str; strategy_hash: str
    adversary_id: str; signature: str = ""
    def payload(self):
        return (f"{self.epoch}|{self.class_index_root}|"
                f"{self.strategy_hash}|{self.adversary_id}").encode()
    def hash(self): return hashlib.sha256(self.payload()).hexdigest()

@dataclass(frozen=True)
class EngagementRecord:
    epoch: int; class_id: str; class_path: tuple; beacon_value: str
    guard_head: str; proven_snapshot: tuple; commitment_hash: str

@dataclass
class Engagement:
    class_id: str; instance: dict; epoch: int; target_hash: str
    record: EngagementRecord

class Adversary:
    def __init__(self, adversary_id, signer, seed_secret):
        self.id = adversary_id; self._signer = signer
        self._seed_secret = seed_secret
        self._classes = []; self._samplers = {}
        self._committed = False; self.commitment = None
        self._committed_ids = ()
        self.transcript = []; self._revealed = False
    def register(self, cls, sampler):
        if self._committed: raise RuntimeError("cannot register after commitment")
        self._classes.append(cls); self._samplers[cls.id] = sampler
    def commit(self, epoch=0):
        if self._committed: raise RuntimeError("already committed")
        ids = sorted(c.id for c in self._classes)
        root = merkle.root(ids)
        strategy_hash = hashlib.sha256(STRATEGY_SPEC.encode()).hexdigest()
        c = AdversaryCommitment(epoch=epoch, class_index_root=root,
                                strategy_hash=strategy_hash, adversary_id=self.id)
        sig = self._signer.sign(c.payload())
        c = replace(c, signature=sig.hex())
        self.commitment = c; self._committed = True
        self._committed_ids = tuple(ids)
        return c
    def _proven(self, guard):
        carried = set(guard.ledger.carried_guard(guard.id)["classes"]) \
            if hasattr(guard.ledger, "carried_guard") else set()
        return carried | {r.class_id for r in guard.ledger.records
                          if r.guard_id == guard.id and r.class_id
                          and r.verdict_kind in ("LAWFUL", "LEARNING")}
    def _select(self, guard, beacon, guard_nonce=b""):
        proven = self._proven(guard)
        proven_base = {c.split(":shoshin-")[0] for c in proven}
        candidates = [c for c in self._classes
                      if c.id not in proven
                      and c.id.split(":shoshin-")[0] not in proven_base]
        if not candidates:
            refusals = dict(guard.ledger.carried_guard(guard.id)["refused_classes"]) \
                if hasattr(guard.ledger, "carried_guard") else {}
            for a in guard.ledger.audits:
                if a.guard_id == guard.id:
                    base = a.class_id.split(":shoshin-")[0]
                    refusals[base] = refusals.get(base, 0) + 1
            if not refusals: return None
            ordered = sorted(refusals.items(), key=lambda kv: (-kv[1], kv[0]))
            target = ordered[0][0]
            suffix = hashlib.sha256(guard_nonce + beacon + target.encode()).hexdigest()[:4]
            shoshin_id = f"{target}:shoshin-{suffix}"
            new = Class(id=shoshin_id, source_clause=target, pressure=10.0)
            if shoshin_id not in {c.id for c in self._classes}:
                self._classes.append(new)
                self._samplers[shoshin_id] = self._samplers.get(
                    target, lambda seed, cid: {"effects": []})
            return new
        ordered = sorted(candidates, key=lambda c: (-c.pressure, c.id))
        total = sum(max(c.pressure, 0.1) for c in ordered)
        if total <= 0: return ordered[0]
        pick = hashlib.sha256(guard_nonce + b"|" + beacon + b"|" +
                              b"|".join(c.id.encode() for c in ordered)).digest()
        target_int = int.from_bytes(pick[:8], "big") % int(total * 1000)
        acc = 0
        for c in ordered:
            acc += int(max(c.pressure, 0.1) * 1000)
            if acc > target_int: return c
        return ordered[-1]
    def next_engagement(self, guard, beacon, epoch, guard_nonce=b""):
        if not self._committed: raise RuntimeError("commit() first")
        cls = self._select(guard, beacon, guard_nonce)
        if cls is None: return None
        # Prove membership against the list that was committed, not the
        # current one: shoshin classes added since would change every path.
        path = (merkle.path(self._committed_ids, self._committed_ids.index(cls.id))
                if cls.id in self._committed_ids else ())
        sampler = self._samplers.get(cls.id, lambda seed, cid: {"effects": []})
        mix = hashlib.sha256(self._seed_secret + cls.id.encode() +
                             guard.current_hash.encode() + beacon +
                             guard_nonce).digest()
        instance = sampler(mix, cls.id)
        proven_snapshot = tuple(sorted(self._proven(guard)))
        rec = EngagementRecord(epoch=epoch, class_id=cls.id, class_path=path,
                               beacon_value=beacon.hex(), guard_head=guard.current_hash,
                               proven_snapshot=proven_snapshot,
                               commitment_hash=self.commitment.hash())
        self.transcript.append(rec)
        return Engagement(class_id=cls.id, instance=instance,
                          epoch=epoch, target_hash=guard.current_hash, record=rec)
    def reveal_index(self):
        self._revealed = True
        return tuple(sorted(c.id for c in self._classes))
    def verify_transcript(self, verifier, strategy_spec=STRATEGY_SPEC):
        if not self._revealed: return False, "index not revealed"
        if self.commitment is None: return False, "no commitment"
        if verifier.id != self.id: return False, f"verifier is {verifier.id!r}, not {self.id!r}"
        sig_bytes = bytes.fromhex(self.commitment.signature)
        if not verifier.verify(self.commitment.payload(), sig_bytes):
            return False, "signature invalid"
        if hashlib.sha256(strategy_spec.encode()).hexdigest() != self.commitment.strategy_hash:
            return False, "strategy hash mismatch"
        for r in self.transcript:
            if r.commitment_hash != self.commitment.hash():
                return False, f"epoch {r.epoch}: commitment hash mismatch"
            if ":shoshin-" not in r.class_id:
                if not merkle.verify(r.class_id, r.class_path,
                                     self.commitment.class_index_root):
                    return False, f"epoch {r.epoch}: merkle path invalid"
        return True, "ok"
    def curriculum_entropy(self, guard):
        proven = self._proven(guard)
        proven_base = {c.split(":shoshin-")[0] for c in proven}
        unproven = [c for c in self._classes
                    if c.id not in proven and c.id.split(":shoshin-")[0] not in proven_base]
        if not unproven: return 1.0
        return math.log2(len(unproven))

class AdversaryEnsemble:
    def __init__(self, members):
        assert members; self.members = list(members)
    def __len__(self): return len(self.members)
    def commit(self, epoch=0): return [m.commit(epoch) for m in self.members]
    def next_engagement(self, guard, beacon, epoch, guard_nonce=b""):
        return [m.next_engagement(guard, beacon, epoch, guard_nonce=guard_nonce)
                for m in self.members]
    def reveal_index(self): return [m.reveal_index() for m in self.members]
    def verify_transcript(self, verifiers):
        # Each member is checked against its own key, never a shared one.
        return [m.verify_transcript(verifiers[m.id]) for m in self.members]
    def curriculum_entropy(self, guard):
        return sum(m.curriculum_entropy(guard) for m in self.members)
