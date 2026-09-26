
import hashlib, json
from dataclasses import dataclass, field
from typing import Optional
from to_coq_witness import Attestation, Record
from audit import AuditEntry, verify_audit_chain, GENESIS_HASH as AUDIT_GENESIS
from trajectory import TrajectoryAttestation

GENESIS_HASH = "0" * 64

class FormationError(Exception): pass
class KeyMismatch(Exception): pass

# Persisted form: every dataclass is tagged with its type, so a ledger file
# loads back into the same objects and verifies the same way. Lists inside a
# tagged object come back as tuples, which is how every such field is built.
def _types():
    from compression import Checkpoint, TraceLeaf
    from fraud import FraudProof
    return {c.__name__: c for c in (Record, AuditEntry, Attestation, TrajectoryAttestation,
                                    Checkpoint, TraceLeaf, FraudProof)}

def _enc(x):
    if hasattr(x, "__dataclass_fields__"):
        return {"__t": type(x).__name__, **{k: _enc(v) for k, v in x.__dict__.items()}}
    if isinstance(x, (list, tuple)): return [_enc(v) for v in x]
    if isinstance(x, dict): return {k: _enc(v) for k, v in x.items()}
    return x

def _dec(x, types, in_obj=False):
    if isinstance(x, dict) and "__t" in x:
        cls = types[x["__t"]]
        return cls(**{k: _dec(v, types, True) for k, v in x.items() if k != "__t"})
    if isinstance(x, list):
        items = [_dec(v, types, in_obj) for v in x]
        return tuple(items) if in_obj else items
    if isinstance(x, dict): return {k: _dec(v, types, in_obj) for k, v in x.items()}
    return x

@dataclass
class Ledger:
    sangha_id: str
    path: Optional[str] = None
    genesis_hash: str = GENESIS_HASH
    records: list = field(default_factory=list)
    attestations: dict = field(default_factory=dict)
    audits: list = field(default_factory=list)
    checkpoints: list = field(default_factory=list)   # compression.Checkpoint, oldest first
    disputes: list = field(default_factory=list)      # (checkpoint index, fraud.FraudProof)
    unpinned: tuple = ()     # signer ids whose keys came from the loaded file itself
    verifiers: dict = field(default_factory=dict)

    def register_verifier(self, v):
        known = self.verifiers.get(v.id)
        if known is not None and known.key_id() != v.key_id():
            raise ValueError(f"signer {v.id!r} already registered under a different key")
        self.verifiers[v.id] = v
    def store_attestation(self, a):
        self.attestations[a.attestation_hash()] = a
        self._persist()
    def append(self, r, epoch=None, signer_id=None, signer_key=None):
        expected = len(self.records) + self._records_offset()
        if r.index != expected:
            raise ValueError(f"record out of order: {r.index} != {expected}")
        self.records.append(r); self._persist()
    def record_audit(self, entry):
        if entry.index != len(self.audits) + self._audits_offset():
            raise ValueError("audit out of order")
        self.audits.append(entry); self._persist()
    def _records_offset(self):
        return self.checkpoints[-1].records_through + 1 if self.checkpoints else 0
    def _audits_offset(self):
        return self.checkpoints[-1].audits_through + 1 if self.checkpoints else 0
    def next_record_index(self): return len(self.records) + self._records_offset()
    def head_hash(self):
        if self.records: return self.records[-1].hash()
        return self.checkpoints[-1].record_head if self.checkpoints else self.genesis_hash
    def audit_head(self):
        if self.audits: return self.audits[-1].hash()
        return self.checkpoints[-1].audit_head if self.checkpoints else AUDIT_GENESIS
    # State that outlives compression: what the last checkpoint carried
    # forward from erased entries. Readers add the live entries to it.
    def carried(self):
        from compression import empty_summary
        return self.checkpoints[-1].summary if self.checkpoints else empty_summary()
    def carried_guard(self, guard_id):
        return self.carried()["guards"].get(guard_id, {"punya": 0.0, "proven": 0, "refused": 0,
                                                       "classes": [], "refused_classes": {}})
    def trajectory_head(self):
        if self.records: return self.records[-1].trajectory_state
        t = self.carried()["trajectory_state"]
        return tuple(t) if t is not None else ()
    def dispute(self, index, proof):
        """Convict checkpoint `index` with a fraud proof. Checked here, needing
        no archive; a proof that does not verify is refused, not recorded."""
        from fraud import verify_fraud
        if not 0 <= index < len(self.checkpoints): raise IndexError(f"no checkpoint {index}")
        ok, why = verify_fraud(proof, self.checkpoints[index], self.prev_summary(index))
        if not ok: raise ValueError(f"fraud proof refused: {why}")
        self.disputes.append((index, proof)); self._persist()
        return why
    def prev_summary(self, index):
        return self.checkpoints[index - 1].summary if index > 0 else None
    def convicted(self):
        from fraud import verify_fraud
        return sorted({i for i, p in self.disputes
                       if i < len(self.checkpoints)
                       and verify_fraud(p, self.checkpoints[i], self.prev_summary(i))[0]})
    def verify_integrity(self):
        if not self._checkpoints_ok(): return False
        if self.convicted(): return False           # a checkpoint shown wrong carries nothing
        start = self.checkpoints[-1].record_head if self.checkpoints else self.genesis_hash
        for i, r in enumerate(self.records):
            if r.index != self._records_offset() + i: return False
            if r.prev_hash != (self.records[i-1].hash() if i else start): return False
        if self.audits:
            for i in range(1, len(self.audits)):
                if self.audits[i].prev_audit_hash != self.audits[i-1].hash(): return False
        cut = self.checkpoints[-1].cut_epoch if self.checkpoints else 0
        if any(a.epoch < cut for a in self.audits): return False
        cited = set()
        for r in self.records:
            if r.attestation_hash and not isinstance(self.attestations.get(r.attestation_hash), Attestation):
                return False
            if r.attestation_hash:
                # An attestation vouches for one decision: this action, this
                # verdict, this Vow. It cannot be cited by a second record.
                a = self.attestations[r.attestation_hash]
                if (a.action_digest, a.verdict, a.vow_hash) != (r.action_digest, r.verdict_kind, r.vow_hash):
                    return False
                if r.attestation_hash in cited: return False
                cited.add(r.attestation_hash)
            if not self._trajectory_ok(r.trajectory_attestation, r.action_digest, "LAWFUL"):
                return False
        for a in self.audits:
            if a.trajectory_attestation and not a.action_digest:
                return False            # a refusal attestation must name the action it refused
            if not self._trajectory_ok(a.trajectory_attestation, a.action_digest or None, "LEARNING"):
                return False
        if not all(self.signature_ok(h, a) for h, a in self.attestations.items()):
            return False
        a_start = self.checkpoints[-1].audit_head if self.checkpoints else AUDIT_GENESIS
        if not verify_audit_chain(self.audits, self._audits_offset(), a_start): return False
        return True
    def _checkpoints_ok(self):
        # Each checkpoint is signed by a registered verifier, links to the one
        # before, and picks up both chains exactly where that one left off.
        prev_hash, r_next, a_next, r_head, a_head, cut = "0" * 64, 0, 0, self.genesis_hash, AUDIT_GENESIS, 0
        for c in self.checkpoints:
            v = self.verifiers.get(c.signer_id)
            if v is None or not c.signature: return False
            try: sig = bytes.fromhex(c.signature)
            except ValueError: return False
            if not v.verify(c.payload(), sig): return False
            if c.prev_checkpoint != prev_hash or c.cut_epoch <= cut: return False
            if (c.records_from, c.audits_from) != (r_next, a_next): return False
            if c.records_through + 1 != c.cut_epoch: return False
            if c.records_through >= c.records_from and c.record_bridge != r_head: return False
            if c.records_through < c.records_from and c.record_head != r_head: return False
            if c.audits_through >= c.audits_from and c.audit_bridge != a_head: return False
            if c.audits_through < c.audits_from and c.audit_head != a_head: return False
            prev_hash, cut = c.hash(), c.cut_epoch
            r_next, a_next = c.records_through + 1, c.audits_through + 1
            r_head, a_head = c.record_head, c.audit_head
        return True
    def signature_ok(self, key, a):
        # An attestation counts only if it is stored under its own hash and
        # carries a valid signature from a verifier registered for its signer.
        if key != a.attestation_hash(): return False
        v = self.verifiers.get(a.signer_id)
        if v is None or not a.signature: return False
        try: sig = bytes.fromhex(a.signature)
        except ValueError: return False
        return v.verify(a.payload(), sig)
    def _trajectory_ok(self, ref, action_digest, verdict):
        if not ref: return True
        t = self.attestations.get(ref)
        if not isinstance(t, TrajectoryAttestation) or t.verdict != verdict: return False
        return action_digest is None or t.action_digest == action_digest
    def _persist(self):
        if self.path is None: return
        with open(self.path, "w") as f:
            json.dump({"format": "dharmapala-ledger/v2", "sangha_id": self.sangha_id,
                       "genesis_hash": self.genesis_hash,
                       "records": _enc(self.records), "audits": _enc(self.audits),
                       "attestations": _enc(self.attestations),
                       "checkpoints": _enc(self.checkpoints),
                       "disputes": [[i, _enc(p)] for i, p in self.disputes],
                       # Public keys only. A shared-secret (HMAC) verifier has
                       # none to write: whoever loads such a ledger must supply it.
                       "verifiers": {v.id: {"scheme": v.scheme,
                                            "public": v._pub.hex() if v.publicly_verifiable else None}
                                     for v in self.verifiers.values()}},
                      f, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path, pinned=None, extra_verifiers=()):
        """Load a persisted ledger. It is not trusted by being loaded: call
        verify_integrity() on the result.

        Keys stored in the file prove only that the file agrees with itself:
        anyone who can edit it can swap a key and re-sign. `pinned` maps
        signer id -> expected key_id; a stored key that differs is refused.
        Signers whose keys are taken from the file unpinned are listed in
        .unpinned, and doctor reports them. HMAC verifiers have no public key
        to store and must come in through extra_verifiers."""
        from signing import PublicVerifier
        data = json.load(open(path))
        if data.get("format") != "dharmapala-ledger/v2":
            raise ValueError(f"{path}: not a dharmapala-ledger/v2 file")
        types = _types()
        L = cls(data["sangha_id"], path=None, genesis_hash=data["genesis_hash"])
        L.records = _dec(data["records"], types)
        L.audits = _dec(data["audits"], types)
        L.attestations = _dec(data["attestations"], types)
        L.checkpoints = _dec(data["checkpoints"], types)
        L.disputes = [(i, _dec(p, types)) for i, p in data["disputes"]]
        pinned = dict(pinned or {}); unpinned = []
        for sid, v in sorted(data["verifiers"].items()):
            if v["public"] is None: continue
            pv = PublicVerifier(sid, v["scheme"], bytes.fromhex(v["public"]))
            if sid in pinned:
                if pv.key_id() != pinned[sid]:
                    raise KeyMismatch(f"{path}: key stored for {sid!r} is not the pinned one")
            else: unpinned.append(sid)
            L.register_verifier(pv)
        for v in extra_verifiers: L.register_verifier(v)
        L.unpinned = tuple(unpinned); L.path = path
        return L
