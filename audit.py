
import hashlib
from dataclasses import dataclass

GENESIS_HASH = "0" * 64

@dataclass(frozen=True)
class AuditEntry:
    index: int; prev_audit_hash: str; record_head_ref: str; epoch: int
    guard_id: str; class_id: str; reason: str; co_signer_notes: tuple
    certificate_path: str; attestation_hash: str
    trajectory_attestation: str; timestamp: float
    # The action refused, so an attestation on this entry is bound to it.
    # Empty only for entries that refuse no single action.
    action_digest: str = ""
    def hash(self):
        payload = (f"{self.index}|{self.prev_audit_hash}|{self.record_head_ref}|"
                   f"{self.epoch}|{self.guard_id}|{self.class_id}|"
                   f"{self.reason}|{'~'.join(self.co_signer_notes)}|"
                   f"{self.certificate_path}|{self.attestation_hash}|"
                   f"{self.trajectory_attestation}|{self.timestamp}|"
                f"{self.action_digest}")
        return hashlib.sha256(payload.encode()).hexdigest()

def verify_audit_chain(audits, start_index=0, start_hash=GENESIS_HASH):
    # start_index and start_hash are where a compression checkpoint left the
    # chain (compression.py); a ledger never compressed starts at genesis.
    for i, a in enumerate(audits):
        expected = audits[i - 1].hash() if i > 0 else start_hash
        if a.prev_audit_hash != expected: return False
        if a.index != start_index + i: return False
    return True
