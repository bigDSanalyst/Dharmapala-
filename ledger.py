
import hashlib, json
from dataclasses import dataclass, field
from typing import Optional
from to_coq_witness import Attestation, Record
from audit import AuditEntry, verify_audit_chain, GENESIS_HASH as AUDIT_GENESIS

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
        if self.records:
            for i in range(1, len(self.records)):
                if self.records[i].prev_hash != self.records[i-1].hash(): return False
        if self.audits:
            for i in range(1, len(self.audits)):
                if self.audits[i].prev_audit_hash != self.audits[i-1].hash(): return False
        for r in self.records:
            if r.attestation_hash and r.attestation_hash not in self.attestations:
                return False
        if not verify_audit_chain(self.audits): return False
        return True
    def _persist(self):
        if self.path is None: return
        with open(self.path, "w") as f:
            json.dump({"sangha_id": self.sangha_id,
                       "records": [r.__dict__ for r in self.records],
                       "attestations": {h: a.__dict__ for h, a in self.attestations.items()},
                       "audits": [a.__dict__ for a in self.audits]},
                      f, indent=2, sort_keys=True, default=str)
