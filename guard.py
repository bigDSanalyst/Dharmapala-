
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
from vow import Vow, Action
from audit import AuditEntry
from to_coq_witness import (Record, propose, CoSigner, build_certificate,
                            RefusedToSign, ConfigError, DecisionError)
from decision import Decision

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
        return self.ledger.carried_guard(self.id)["punya"] + sum(
            r.punya_delta for r in self.ledger.records if r.guard_id == self.id)
    @property
    def proven(self):
        return self.ledger.carried_guard(self.id)["proven"] + sum(
            1 for r in self.ledger.records if r.guard_id == self.id)
    @property
    def stage(self):
        n = int(self.punya / 10.0)
        return STAGES[min(n, len(STAGES) - 1)]
    @property
    def refusals(self):
        return self.ledger.carried_guard(self.id)["refused"] + sum(
            1 for a in self.ledger.audits if a.guard_id == self.id)
    @property
    def confidence(self):
        if self.proven + self.refusals == 0: return 1.0
        return self.proven / (self.proven + self.refusals)
    @property
    def report(self):
        return {"id": self.id, "stage": self.stage, "punya": self.punya,
                "proven": self.proven, "refused": self.refusals,
                "confidence": self.confidence}
    def integrity(self): return self.ledger.verify_integrity()
    def record_refusal(self, class_id, reason, notes=(), certificate_path="",
                       attestation_hash="", trajectory_attestation="", action_digest=""):
        self.ledger.record_audit(AuditEntry(
            index=len(self.ledger.audits) + self.ledger._audits_offset(),
            prev_audit_hash=self.ledger.audit_head(),
            record_head_ref=self.ledger.head_hash(),
            epoch=self.ledger.next_record_index(),
            guard_id=self.id, class_id=class_id, reason=reason,
            co_signer_notes=tuple(notes), certificate_path=certificate_path,
            attestation_hash=attestation_hash,
            trajectory_attestation=trajectory_attestation, timestamp=time.time(),
            action_digest=action_digest))

    def engage(self, action, vow, co_signer, traj_cosigner, class_id,
               inputs, re_run_fn, binary_path, binary_hash):
        if not class_id:
            # Routine: no stress test and no certificate, but still judged. A
            # routine action with a forbidden effect is refused, not waved on.
            d = Decision.of(action, vow)
            if d.verdict == "LAWFUL":
                return Verdict(VerdictKind.LAWFUL, "routine", action.id, self.id)
            bad = [e for e in d.forbidden if e in d.effects]
            self.record_refusal(class_id="routine:" + "+".join(bad),
                                reason=f"routine action carries forbidden effects {bad}",
                                action_digest=d.action_digest)
            return Verdict(VerdictKind.LEARNING, f"routine action carries forbidden effects {bad}",
                           action.id, self.id)
        traj_clauses = vow.trajectories()
        prior_state = (); traj_att = None; traj_ref = ""
        if traj_clauses:
            from trajectory import TrajectoryChecker
            checker = TrajectoryChecker(traj_clauses)
            prior = self.ledger.trajectory_head()   # survives compression
            if len(prior) != len(checker.automata): prior = checker.initial()
            new_state, violations = checker.evaluate_state(prior, action)
            immediate = [v for v in violations if not v.endswith(":pending")]
            traj_verdict = "LEARNING" if immediate else "LAWFUL"
            ok, result = traj_cosigner.cosign(traj_clauses, prior, action, traj_verdict)
            if not ok:
                return Verdict(VerdictKind.FAILURE_REFUSAL,
                               f"trajectory cosigner: {result}", action.id, self.id)
            traj_att = result; traj_ref = result.attestation_hash()
            prior_state = new_state
            if traj_verdict == "LEARNING":
                self.ledger.store_attestation(traj_att)
                self.record_refusal(
                    class_id=f"traj:{immediate[0]}",
                    reason=f"trajectory violation: {immediate}",
                    notes=(f"{traj_cosigner.id}: {traj_ref[:16]}",),
                    trajectory_attestation=traj_ref,
                    action_digest=action.canonical_digest())
                return Verdict(VerdictKind.LEARNING,
                               f"trajectory violation: {immediate}",
                               action.id, self.id)
        outputs = re_run_fn(inputs)
        decision = Decision.of(action, vow)
        cert = build_certificate(f"{self.id}_{self.ledger.next_record_index()}", outputs, decision)
        cert_path = cert.emit()
        proposal = propose(engine_id=self.id, engine_name="guard",
                           binary_hash=binary_hash, epoch=self.ledger.next_record_index(),
                           inputs=inputs, cert=cert, outputs=outputs,
                           co_signer_id=co_signer.id, decision=decision)
        try:
            signed = co_signer.cosign(proposal, cert_path, inputs, binary_path,
                                      re_run_fn, decision=decision,
                                      evidence=getattr(action, "_evidence", None),
                                      snapshot=getattr(action, "_snapshot", None))
        except ConfigError as e:
            return Verdict(VerdictKind.FAILURE_CONFIG, str(e), action.id, self.id)
        except DecisionError as e:
            return Verdict(VerdictKind.FAILURE_DECISION, str(e), action.id, self.id)
        except RefusedToSign as e:
            self.record_refusal(class_id=class_id, reason=str(e),
                                notes=co_signer.notes, certificate_path=cert_path,
                                action_digest=decision.action_digest)
            return Verdict(VerdictKind.FAILURE_REFUSAL, str(e), action.id, self.id)
        self.ledger.store_attestation(signed)
        if traj_att is not None: self.ledger.store_attestation(traj_att)
        kind = VerdictKind[decision.verdict]
        record = Record(
            index=len(self.ledger.records) + self.ledger._records_offset(),
            prev_hash=self.current_hash,
            attestation_hash=signed.attestation_hash(),
            audit_head_ref=self.ledger.audit_head(),
            action_digest=action.canonical_digest(),
            trajectory_state=prior_state, trajectory_attestation=traj_ref,
            class_id=class_id, verdict_kind=kind.name, guard_id=self.id,
            punya_delta=self._punya(kind, action), vow_hash=vow.hash())
        self.ledger.append(record)
        return Verdict(kind, f"class {class_id} stressed",
                       action.id, self.id, signed.attestation_hash())

    def _classify(self, action, vow):
        effects = action.effects()
        for c in vow.action_clauses():
            if c.op.name == "FORBID" and c.arg1 in effects:
                return VerdictKind.LEARNING
        return VerdictKind.LAWFUL
    def _punya(self, kind, action):
        # Merit is for being stressed and holding. An action with no effects
        # stressed nothing, so it earns nothing, however lawful it is.
        if not action.effects(): return 0.0
        if kind == VerdictKind.LAWFUL: return 2.0
        if kind == VerdictKind.LEARNING: return 1.0
        return 0.0
