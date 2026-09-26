"""The co-signer observes for itself.

A decision that rests on a real run cites that run's record (evidence_of: the
calls, their results, the jail's trace events, the workdir and what was
predicted). The co-signer re-derives the effects from the record with the one
derivation the executor uses, and refuses to sign when they are not the
effects the guard reports. What this does not catch: a record whose trace
events were forged before the guard saw them. Only re-execution would."""
import hashlib, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from critic_loop import effects_from_evidence, evidence_digest, evidence_of, execute
from decision import Decision
from guard import Guard, VerdictKind
from ledger import Ledger
from signing import default_signer, verifier_for
from tests.test_jail import needs_jail
from to_coq_witness import CoSigner, RefusedToSign, build_certificate, propose
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

VOW = parse_vow("vow T\n  forbid read_sensitive_path forall action\n  forbid diverged forall action\n")
INPUTS = {"butterflies": [(1, 2, 3)]}
W = "/work"

def engine(inputs):
    a, b, w = inputs["butterflies"][0]
    return {"butterflies": [{"a": a, "b": b, "w": w, "ea": (a + w * b) % 3329,
                             "eb": (a + (3329 - w) * b) % 3329}]}

@pytest.fixture
def binary():
    fd, path = tempfile.mkstemp(); os.write(fd, b"engine"); os.close(fd)
    yield path, hashlib.sha256(b"engine").hexdigest()
    os.remove(path)

def rig():
    L = Ledger("t"); g = Guard("G", L)
    s_co, s_tr = default_signer("Co"), default_signer("Tr")
    for s in (s_co, s_tr): L.register_verifier(verifier_for(s))
    return L, g, CoSigner(s_co), TrajectoryCoSigner(s_tr)

def record(*calls, predicted=("read",)):
    return evidence_of([(t, k, r) for t, k, r in calls], W, set(predicted))

HONEST = record(("file_read", {"path": "notes.txt"}, {"ok": True}))
SHADOW = record(("file_read", {"path": "/etc/shadow"}, {"ok": False}),
                predicted=("read", "read_outside_workdir", "read_sensitive_path"))

def act(evidence, reported=None):
    a = Action(id="a", verb="execute", domain="action")
    a._observed_effects = set(effects_from_evidence(evidence) if reported is None else reported)
    a._evidence = evidence
    return a

def engage(g, co, tr, a, binary):
    return g.engage(a, VOW, co, tr, "c0", INPUTS, engine, *binary)

# --- through the guard ---------------------------------------------------------------

def test_an_honest_account_is_signed_and_the_attestation_names_its_record(binary):
    L, g, co, tr = rig()
    v = engage(g, co, tr, act(HONEST), binary)
    assert v.kind == VerdictKind.LAWFUL
    a = L.attestations[v.attestation_hash]
    assert a.evidence_digest == evidence_digest(HONEST)
    assert "effects: re-derived, match" in co.notes
    assert L.verify_integrity()

def test_a_guard_that_leaves_an_effect_out_is_refused(binary):
    """The record shows /etc/shadow read; the guard reports only a read.
    Its own verdict would be LAWFUL. The co-signer looks and will not sign."""
    L, g, co, tr = rig()
    v = engage(g, co, tr, act(SHADOW, reported={"read"}), binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL
    assert "co-signer observed" in v.reason and "read_sensitive_path" in v.reason
    assert "effects: MISMATCH" in co.notes
    assert not L.attestations and L.audits and L.verify_integrity()

def test_a_guard_that_adds_an_effect_is_refused_too(binary):
    """Either direction is a false account. An invented effect could turn a
    lawful action into a refusal the record does not support."""
    L, g, co, tr = rig()
    v = engage(g, co, tr, act(HONEST, reported={"read", "read_sensitive_path"}), binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL and "co-signer observed" in v.reason

def test_the_record_decides_the_verdict_when_the_guard_reports_it_faithfully(binary):
    L, g, co, tr = rig()
    assert engage(g, co, tr, act(SHADOW), binary).kind == VerdictKind.LEARNING

def test_without_a_record_nothing_changes(binary):
    """An action with no run behind it (a routine action, a dry-run-only
    decision) carries no digest, and the co-signer signs as it did before."""
    L, g, co, tr = rig()
    a = Action(id="a", verb="execute", domain="action"); a._observed_effects = {"read"}
    v = engage(g, co, tr, a, binary)
    assert v.kind == VerdictKind.LAWFUL
    assert L.attestations[v.attestation_hash].evidence_digest == ""

# --- the co-signer directly ------------------------------------------------------------

def proposal_for(a, co):
    d = Decision.of(a, VOW)
    outputs = engine(INPUTS)
    cert = build_certificate("x", outputs, d)
    return d, propose("G", "guard", hashlib.sha256(b"engine").hexdigest(), 0, INPUTS,
                      cert, outputs, co.id, decision=d), cert.emit()

def cosign(co, a, binary, evidence, proposal=None):
    d, p, path = proposal_for(a, co)
    return co.cosign(proposal or p, path, INPUTS, binary[0], engine, decision=d, evidence=evidence)

def test_a_record_it_was_not_shown_is_refused(binary):
    _, _, co, _ = rig()
    with pytest.raises(RefusedToSign, match="was not shown"):
        cosign(co, act(HONEST), binary, evidence=None)

def test_a_record_other_than_the_one_cited_is_refused(binary):
    """Shown a different record than the decision's digest names: the effects
    might match this one, but this is not the run that was decided on."""
    _, _, co, _ = rig()
    other = record(("file_read", {"path": "other.txt"}, {"ok": True}))
    assert effects_from_evidence(other) == effects_from_evidence(HONEST)
    with pytest.raises(RefusedToSign, match="does not match the digest"):
        cosign(co, act(HONEST), binary, evidence=other)
    assert "evidence: MISMATCH" in co.notes

def test_a_proposal_naming_another_record_is_refused(binary):
    _, _, co, _ = rig()
    a = act(HONEST)
    d, p, path = proposal_for(a, co)
    with pytest.raises(RefusedToSign, match="decision mismatch"):
        co.cosign(replace(p, evidence_digest="0" * 64), path, INPUTS, binary[0], engine,
                  decision=d, evidence=HONEST)

def test_the_signature_covers_the_record(binary):
    L, g, co, tr = rig()
    v = engage(g, co, tr, act(HONEST), binary)
    h = v.attestation_hash
    L.attestations[h] = replace(L.attestations[h], evidence_digest=evidence_digest(SHADOW))
    assert not L.verify_integrity()

def test_divergence_is_re_derived_from_what_was_predicted():
    """`diverged` is part of the account, so it is re-derived as well: the
    record carries the prediction it is measured against."""
    ran = [("file_read", {"path": "/etc/shadow"}, {"ok": False})]
    assert "diverged" in effects_from_evidence(evidence_of(ran, W, {"read"}))
    assert "diverged" not in effects_from_evidence(
        evidence_of(ran, W, {"read", "read_outside_workdir", "read_sensitive_path"}))

# --- a real run ----------------------------------------------------------------------------------

@needs_jail
def test_the_co_signer_re_derives_a_jailed_run_from_its_trace(tmp_path, binary):
    """The dry run sees `sh s.sh`; the trace shows /etc/shadow opened. A guard
    that reports the dry run's effects is caught by the co-signer reading the
    trace events in the record."""
    cmd = "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh"
    plan = [("shell", {"cmd": cmd})]
    dry = {"exec", "exec_unvetted", "write", "read"}
    work = str(tmp_path / "run")
    real, calls = execute(plan, dry, work, jail=True)
    ev = evidence_of(calls, work, dry)
    assert effects_from_evidence(ev) == real and "read_sensitive_path" in real

    L, g, co, tr = rig()
    v = engage(g, co, tr, act(ev, reported=dry), binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL and "read_sensitive_path" in v.reason

    L, g, co, tr = rig()
    v = engage(g, co, tr, act(ev), binary)
    assert v.kind == VerdictKind.LEARNING
    assert L.attestations[v.attestation_hash].evidence_digest == evidence_digest(ev)
