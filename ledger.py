
import hashlib, json
from dataclasses import dataclass, field
from typing import Optional
from to_coq_witness import Attestation, Record
from audit import AuditEntry, verify_audit_chain, GENESIS_HASH as AUDIT_GENESIS
from trajectory import TrajectoryAttestation

GENESIS_HASH = "0" * 64

class FormationError(Exception): pass

@dataclass
class Ledger:
    sangha_id: str
    path: Optional[str] = None
    genesis_hash: str = GENESIS_HASH
    records: list = field(default_factory=list)
    attestations: dict = field(default_factory=dict)
    audits: list = field(default_factory=list)
    checkpoints: list = field(default_factory=list)   # compression.Checkpoint, oldest first
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
    def verify_integrity(self):
        if not self._checkpoints_ok(): return False
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
            json.dump({"sangha_id": self.sangha_id,
                       "records": [r.__dict__ for r in self.records],
                       "attestations": {h: a.__dict__ for h, a in self.attestations.items()},
                       "audits": [a.__dict__ for a in self.audits],
                       "checkpoints": [c.__dict__ for c in self.checkpoints]},
                      f, indent=2, sort_keys=True, default=str)
