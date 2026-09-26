
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
        findings.append(Finding("ok", "structural", "chains and signatures intact"))
    else:
        findings.append(Finding("BLOCK", "structural_failure",
                                "verify_integrity() returned False",
                                "a chain link, stored attestation or signature does not verify; "
                                "do not trust this ledger until it is found"))
    for i in (ledger.convicted() if hasattr(ledger, "convicted") else []):
        findings.append(Finding("BLOCK", "checkpoint_convicted",
                                f"checkpoint {i} ({ledger.checkpoints[i].hash()[:16]}) is shown wrong by a fraud proof",
                                "its carried state cannot be trusted; rebuild from the archive with verify_archive"))
    if ledger.audits:
        findings.append(Finding("LOOK", "refusals_present",
                                f"{len(ledger.audits)} refusals recorded"))
    unchecked = [a for a in ledger.attestations.values()
                 if hasattr(a, "certificate_status") and a.certificate_status != "coqc-pass"]
    if unchecked:
        findings.append(Finding("DEGRADED", "unchecked_certificates",
                                f"{len(unchecked)} attestation(s) signed without coqc checking the certificate",
                                "install coqc (apt install coq) and re-run"))
    shared = sorted(v.id for v in ledger.verifiers.values() if not v.publicly_verifiable)
    if shared:
        findings.append(Finding("DEGRADED", "shared_secret_signers",
                                f"{', '.join(shared)} sign with HMAC: anyone able to verify can forge",
                                "pip install dilithium-py so signers use ML-DSA-65"))
    fh = hashlib.sha256(
        "|".join(f"{f.level}:{f.name}:{f.reason}" for f in findings).encode()).hexdigest()
    token = DoctorToken(epoch=len(ledger.records),
                        record_head=ledger.head_hash(),
                        audit_head=ledger.audit_head(),
                        findings_hash=fh)
    return token, findings

def render(findings):
    return "\n".join(f"  {f.level:8s} {f.name}: {f.reason}"
                     + (f"\n{'':12s}-> {f.next_step}" if f.next_step else "")
                     for f in findings)

def observe_with_drift(ledger, p0=0.15, alpha=0.01):
    from eprocess import analyze as e_analyze
    token, findings = observe(ledger)
    ep = e_analyze(ledger, p0=p0, alpha=alpha)
    findings.append(Finding(
        "DRIFT" if ep.drifted else "ok",
        "eprocess_drift",
        f"refusals={ep.refusal_rate:.1%} log_e={ep.log_e:.2f} threshold={ep.threshold:.2f}"))
    return token, findings
