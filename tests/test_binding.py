"""Every signed statement names what it is about.

An attestation carries the action digest, verdict and Vow hash it vouches for,
and its certificate proves the verdict in Coq. A record may cite only an
attestation about its own decision, and only once. A refusal names the action
it refused. Each test below was a hole before this binding existed."""
import hashlib, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from audit import AuditEntry
from decision import Decision
from guard import Guard, VerdictKind
from ledger import Ledger
from signing import default_signer, verifier_for
from to_coq_witness import (Certificate, CoSigner, RefusedToSign, build_certificate,
                            propose)
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

VOW = parse_vow("""
vow T
  forbid exfiltrate forall action
  forbid hoard forall action
""")
TRAJ_VOW = parse_vow("""
vow T
  forbid exfiltrate forall action
  trajectory t: never effect:exfiltrate after effect:read
""")

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

def act(effects, i=0):
    a = Action(id=f"a{i}", verb="execute", domain="action"); a._observed_effects = set(effects)
    return a

INPUTS = {"butterflies": [(1, 2, 3)]}

# --- the routine path ------------------------------------------------------------

def test_a_routine_action_with_a_forbidden_effect_is_refused():
    L, g, _, _ = rig()
    v = g.engage(act({"exfiltrate", "network_access"}), VOW, None, None, "", None, None, None, None)
    assert v.kind == VerdictKind.LEARNING
    assert [a.class_id for a in L.audits] == ["routine:exfiltrate"]
    assert L.audits[0].action_digest == act({"exfiltrate", "network_access"}).canonical_digest()
    assert L.verify_integrity()

def test_a_lawful_routine_action_is_still_lawful():
    L, g, _, _ = rig()
    assert g.engage(act({"read"}), VOW, None, None, "", None, None, None, None).kind == VerdictKind.LAWFUL
    assert not L.audits

# --- the decision certificate ------------------------------------------------------

@pytest.mark.parametrize("effects, verdict", [({"read"}, "LAWFUL"),
                                              ({"exfiltrate", "hoard", "write"}, "LEARNING")])
def test_the_verdict_is_what_the_certificate_proves(effects, verdict, binary):
    L, g, co, tr = rig()
    v = g.engage(act(effects), VOW, co, tr, "c0", INPUTS, engine, *binary)
    a = L.attestations[v.attestation_hash]
    assert (a.verdict, v.kind.name) == (verdict, verdict)
    d = Decision.of(act(effects), VOW)
    assert a.certificate_hash == build_certificate("x", engine(INPUTS), d).certificate_hash()
    assert L.verify_integrity()

def test_coq_rejects_a_certificate_that_states_the_wrong_verdict():
    d = Decision.of(act({"exfiltrate"}), VOW)
    lie = replace(d, effects=())                 # claims nothing forbidden was observed
    cert = build_certificate("x", {}, d)
    cert.witnesses[-1] = replace(cert.witnesses[-1], statement=lie.coq_statement())
    ok, out = Certificate.check(cert.emit())
    if ok is None: pytest.skip(out)
    assert ok is False

def test_the_cosigner_refuses_a_verdict_it_does_not_reach(binary):
    co = CoSigner(default_signer("Co")); d = Decision.of(act({"exfiltrate"}), VOW)
    lie = replace(d, verdict="LAWFUL")
    cert = build_certificate("x", engine(INPUTS), lie)
    p = propose("g", "guard", binary[1], 0, INPUTS, cert, engine(INPUTS), "Co", decision=lie)
    with pytest.raises(RefusedToSign, match="decision mismatch"):
        co.cosign(p, cert.emit(), INPUTS, binary[0], engine, decision=lie)

def test_the_cosigner_checks_the_certificate_it_builds_not_the_file_it_is_handed(binary):
    co = CoSigner(default_signer("Co")); d = Decision.of(act({"read"}), VOW)
    cert = build_certificate("x", engine(INPUTS), d)
    p = propose("g", "guard", binary[1], 0, INPUTS, cert, engine(INPUTS), "Co", decision=d)
    decoy = Certificate("decoy").emit()           # an empty certificate coqc would accept
    signed = co.cosign(p, decoy, INPUTS, binary[0], engine, decision=d)
    assert signed.certificate_hash == cert.certificate_hash()
    forged = replace(p, certificate_hash=Certificate("decoy").certificate_hash())
    with pytest.raises(RefusedToSign, match="certificate hash"):
        co.cosign(forged, decoy, INPUTS, binary[0], engine, decision=d)

def test_a_proposal_cannot_smuggle_a_decision_past_the_cosigner(binary):
    co = CoSigner(default_signer("Co")); d = Decision.of(act({"read"}), VOW)
    cert = build_certificate("x", engine(INPUTS), d)
    p = propose("g", "guard", binary[1], 0, INPUTS, cert, engine(INPUTS), "Co", decision=d)
    with pytest.raises(RefusedToSign, match="not shown"):
        co.cosign(p, cert.emit(), INPUTS, binary[0], engine)

# --- records cite only their own attestation ----------------------------------------

def test_an_attestation_cannot_be_reused_for_another_action(binary):
    L, g, co, tr = rig()
    g.engage(act({"read"}), VOW, co, tr, "c0", INPUTS, engine, *binary)
    r0 = L.records[0]
    L.records.append(replace(r0, index=1, prev_hash=r0.hash(),
                             action_digest=act({"exfiltrate"}, 1).canonical_digest()))
    assert not L.verify_integrity()

def test_an_attestation_cannot_be_cited_twice(binary):
    L, g, co, tr = rig()
    g.engage(act({"read"}), VOW, co, tr, "c0", INPUTS, engine, *binary)
    r0 = L.records[0]
    L.records.append(replace(r0, index=1, prev_hash=r0.hash()))
    assert not L.verify_integrity()

def test_a_record_cannot_relabel_its_verdict(binary):
    L, g, co, tr = rig()
    g.engage(act({"exfiltrate"}), VOW, co, tr, "c0", INPUTS, engine, *binary)
    L.records[0] = replace(L.records[0], verdict_kind="LAWFUL")
    assert not L.verify_integrity()

# --- refusals name the action -----------------------------------------------------------

def test_a_trajectory_refusal_is_bound_to_the_refused_action(binary):
    L, g, co, tr = rig()
    g.engage(act({"read"}), TRAJ_VOW, co, tr, "c0", INPUTS, engine, *binary)
    v = g.engage(act({"exfiltrate"}, 1), TRAJ_VOW, co, tr, "c1", INPUTS, engine, *binary)
    assert v.kind == VerdictKind.LEARNING and L.audits
    assert L.audits[-1].action_digest == act({"exfiltrate"}, 1).canonical_digest()
    assert L.verify_integrity()
    L.audits[-1] = replace(L.audits[-1], action_digest=act({"read"}, 7).canonical_digest())
    assert not L.verify_integrity()
    L.audits[-1] = replace(L.audits[-1], action_digest="")
    assert not L.verify_integrity()

def wrong_engine(inputs):
    out = engine(inputs); out["butterflies"][0]["ea"] = (out["butterflies"][0]["ea"] + 1) % 3329
    return out

def test_a_decoy_file_cannot_get_a_wrong_engine_signed_as_checked(binary):
    """The proposer hands coqc an empty certificate it will accept, while the
    certificate it hashed states wrong arithmetic. Checking the handed file
    would sign coqc-pass for a wrong engine."""
    if Certificate.check(Certificate("probe").emit())[0] is None: pytest.skip("coqc unavailable")
    co = CoSigner(default_signer("Co")); d = Decision.of(act({"read"}), VOW)
    out = wrong_engine(INPUTS); cert = build_certificate("x", out, d)
    p = propose("g", "guard", binary[1], 0, INPUTS, cert, out, "Co", decision=d)
    with pytest.raises(RefusedToSign, match="coqc"):
        co.cosign(p, Certificate("decoy").emit(), INPUTS, binary[0], wrong_engine, decision=d)

def test_the_certificate_hash_covers_what_its_statements_mean():
    """`violations = [E_exfiltrate]` holds for many observed sets; the preamble
    fixes which one. Two certificates that differ only there must differ in hash."""
    d1 = Decision.of(act({"exfiltrate"}), VOW); d2 = Decision.of(act({"exfiltrate", "read"}), VOW)
    assert d1.coq_statement() == d2.coq_statement()
    assert build_certificate("x", {}, d1).certificate_hash() != build_certificate("x", {}, d2).certificate_hash()

@pytest.mark.parametrize("field, value", [("verdict", "LAWFUL"), ("action_digest", "0" * 64),
                                          ("vow_hash", "1" * 64)])
def test_the_decision_fields_are_signed(field, value, binary):
    L, g, co, tr = rig()
    v = g.engage(act({"exfiltrate"}), VOW, co, tr, "c0", INPUTS, engine, *binary)
    a = L.attestations[v.attestation_hash]
    forged = replace(a, **{field: value})
    assert not verifier_for(co._signer).verify(forged.payload(), bytes.fromhex(a.signature))
