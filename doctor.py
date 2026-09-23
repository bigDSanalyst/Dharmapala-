
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    level: str; name: str; reason: str; next_step: str = ""

@dataclass(frozen=True)
class DoctorToken:
    epoch: int; record_head: str; audit_head: str; findings_hash: str

def observe(ledger):
    findings = []
    if ledger.verify_integrity():
        findings.append(Finding("ok", "structural", "chains intact"))
    else:
        findings.append(Finding("BLOCK", "structural_failure",
                                "verify_integrity() returned False"))
    if ledger.audits:
        findings.append(Finding("LOOK", "refusals_present",
                                f"{len(ledger.audits)} refusals recorded"))
    fh = hashlib.sha256(
        "|".join(f"{f.level}:{f.name}:{f.reason}" for f in findings).encode()).hexdigest()
    token = DoctorToken(epoch=len(ledger.records),
                        record_head=ledger.head_hash(),
                        audit_head=ledger.audit_head(),
                        findings_hash=fh)
    return token, findings

def render(findings):
    return "\n".join(f"  {f.level:6s} {f.name}: {f.reason}" for f in findings)

def observe_with_drift(ledger, p0=0.15, alpha=0.01):
    from eprocess import analyze as e_analyze
    token, findings = observe(ledger)
    ep = e_analyze(ledger, p0=p0, alpha=alpha)
    findings.append(Finding(
        "DRIFT" if ep.drifted else "ok",
        "eprocess_drift",
        f"refusals={ep.refusal_rate:.1%} log_e={ep.log_e:.2f} threshold={ep.threshold:.2f}"))
    return token, findings
