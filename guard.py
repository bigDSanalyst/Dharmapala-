
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
from vow import Vow, Action
from audit import AuditEntry
from to_coq_witness import (Certificate, Record, propose, CoSigner,
                            RefusedToSign, ConfigError, DecisionError,
                            witness_zq_butterfly)

class VerdictKind(Enum):
    LAWFUL = auto(); LEARNING = auto()
    FAILURE_CONFIG = auto(); FAILURE_DECISION = auto(); FAILURE_REFUSAL = auto()

@dataclass(frozen=True)
class Verdict:
    kind: VerdictKind; reason: str; action_id: str; guard_id: str
    attestation_hash: Optional[str] = None

STAGES = ["NOVICE", "PRACTITIONER", "TEACHER", "SENIOR", "ELDER", "DHARMAPALA"]
GENESIS_HASH = "0" * 64

class Guard:
    def __init__(self, guard_id, ledger, genesis_hash=GENESIS_HASH):
        self.id = guard_id; self.ledger = ledger; self.genesis_hash = genesis_hash
    @property
    def current_hash(self): return self.ledger.head_hash()
    @property
    def punya(self):
        return sum(r.punya_delta for r in self.ledger.records if r.guard_id == self.id)
    @property
    def stage(self):
        n = int(self.punya / 10.0)
        return STAGES[min(n, len(STAGES) - 1)]
    @property
    def refusals(self):
        return sum(1 for a in self.ledger.audits if a.guard_id == self.id)
    @property
    def confidence(self):
        proven = sum(1 for r in self.ledger.records if r.guard_id == self.id)
        if proven + self.refusals == 0: return 1.0
        return proven / (proven + self.refusals)
    @property
    def report(self):
        return {"id": self.id, "stage": self.stage, "punya": self.punya,
                "proven": sum(1 for r in self.ledger.records if r.guard_id == self.id),
                "refused": self.refusals, "confidence": self.confidence}
    def integrity(self): return self.ledger.verify_integrity()

    def engage(self, action, vow, co_signer, traj_cosigner, class_id,
               inputs, re_run_fn, binary_path, binary_hash):
        if not class_id:
            return Verdict(VerdictKind.LAWFUL, "routine", action.id, self.id)
        traj_clauses = vow.trajectories()
        prior_state = (); traj_sig = ""
        if traj_clauses:
            from trajectory import TrajectoryChecker
            checker = TrajectoryChecker(traj_clauses)
            prior = (self.ledger.records[-1].trajectory_state
                     if self.ledger.records else ())
            if len(prior) != len(checker.automata): prior = checker.initial()
            new_state, violations = checker.evaluate_state(prior, action)
            immediate = [v for v in violations if not v.endswith(":pending")]
            traj_verdict = "LEARNING" if immediate else "LAWFUL"
            ok, result = traj_cosigner.cosign(traj_clauses, prior, action, traj_verdict)
            if not ok:
                return Verdict(VerdictKind.FAILURE_REFUSAL,
                               f"trajectory cosigner: {result}", action.id, self.id)
            traj_sig = result; prior_state = new_state
            if traj_verdict == "LEARNING":
                audit = AuditEntry(
                    index=len(self.ledger.audits) + self.ledger._audits_offset(),
                    prev_audit_hash=self.ledger.audit_head(),
                    record_head_ref=self.ledger.head_hash(),
                    epoch=len(self.ledger.records),
                    guard_id=self.id, class_id=f"traj:{immediate[0]}",
                    reason=f"trajectory violation: {immediate}",
                    co_signer_notes=(f"{traj_cosigner.id}: {result[:16]}",),
                    certificate_path="", attestation_hash="",
                    trajectory_signature=traj_sig, timestamp=time.time())
                self.ledger.record_audit(audit)
                return Verdict(VerdictKind.LEARNING,
                               f"trajectory violation: {immediate}",
                               action.id, self.id)
        outputs = re_run_fn(inputs)
        q = 3329
        cert = Certificate(f"{self.id}_{len(self.ledger.records)}")
        for i, b in enumerate(outputs.get("butterflies", [])):
            we, wo = witness_zq_butterfly(q, b["a"], b["b"], b["w"],
                                          b["ea"], b["eb"], i)
            cert.add(we).add(wo)
        cert_path = cert.emit()
        proposal = propose(engine_id=self.id, engine_name="guard",
                           binary_hash=binary_hash, epoch=len(self.ledger.records),
                           inputs=inputs, cert=cert, outputs=outputs,
                           co_signer_id=co_signer.id)
        try:
            signed = co_signer.cosign(proposal, cert_path, inputs, binary_path, re_run_fn)
        except ConfigError as e:
            return Verdict(VerdictKind.FAILURE_CONFIG, str(e), action.id, self.id)
        except DecisionError as e:
            return Verdict(VerdictKind.FAILURE_DECISION, str(e), action.id, self.id)
        except RefusedToSign as e:
            audit = AuditEntry(
                index=len(self.ledger.audits) + self.ledger._audits_offset(),
                prev_audit_hash=self.ledger.audit_head(),
                record_head_ref=self.ledger.head_hash(),
                epoch=len(self.ledger.records),
                guard_id=self.id, class_id=class_id,
                reason=str(e), co_signer_notes=tuple(co_signer.notes),
                certificate_path=cert_path, attestation_hash="",
                trajectory_signature="", timestamp=time.time())
            self.ledger.record_audit(audit)
            return Verdict(VerdictKind.FAILURE_REFUSAL, str(e), action.id, self.id)
        self.ledger.store_attestation(signed)
        kind = self._classify(action, vow)
        record = Record(
            index=len(self.ledger.records) + self.ledger._records_offset(),
            prev_hash=self.current_hash,
            attestation_hash=signed.attestation_hash(),
            audit_head_ref=self.ledger.audit_head(),
            action_digest=action.canonical_digest(),
            trajectory_state=prior_state, trajectory_signature=traj_sig,
            class_id=class_id, verdict_kind=kind.name, guard_id=self.id,
            punya_delta=self._punya(kind, class_id), vow_hash=vow.hash())
        self.ledger.append(record)
        return Verdict(kind, f"class {class_id} stressed",
                       action.id, self.id, signed.attestation_hash())

    def _classify(self, action, vow):
        effects = action.effects()
        for c in vow.action_clauses():
            if c.op.name == "FORBID" and c.arg1 in effects:
                return VerdictKind.LEARNING
        return VerdictKind.LAWFUL
    def _punya(self, kind, class_id):
        if kind == VerdictKind.LAWFUL: return 2.0
        if kind == VerdictKind.LEARNING: return 1.0
        return 0.0
