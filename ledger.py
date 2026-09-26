
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
    compressions: list = field(default_factory=list)
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
        return sum(c.through_index + 1 for c in self.compressions if c.kind == "records")
    def _audits_offset(self):
        return sum(c.through_index + 1 for c in self.compressions if c.kind == "audits")
    def head_hash(self):
        return self.records[-1].hash() if self.records else self.genesis_hash
    def audit_head(self):
        return self.audits[-1].hash() if self.audits else AUDIT_GENESIS
    def verify_integrity(self):
        if self.records and not self._records_offset():
            if self.records[0].prev_hash != self.genesis_hash: return False
        if self.records:
            for i in range(1, len(self.records)):
                if self.records[i].prev_hash != self.records[i-1].hash(): return False
        if self.audits:
            for i in range(1, len(self.audits)):
                if self.audits[i].prev_audit_hash != self.audits[i-1].hash(): return False
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
        if not verify_audit_chain(self.audits): return False
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
                       "audits": [a.__dict__ for a in self.audits]},
                      f, indent=2, sort_keys=True, default=str)
