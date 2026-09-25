import hashlib, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401  (puts the repo on sys.path)
import critic_loop, lake_critic
from agent import Agent
from audit import AuditEntry
from eprocess import outcomes
from guard import Guard, VerdictKind
from ledger import Ledger
from observation import observe
from signing import default_signer, verifier_for
from to_coq_witness import (Certificate, CoSigner, RefusedToSign, Record,
                            propose, witness_zq_butterfly)
from tools import Sandbox
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow
from vow_lean import emit_vow_compliance

VOW = parse_vow("""
vow T
  commit read forall action
  forbid exfiltrate forall action
  forbid hoard forall action
""")

def engine(inputs):
    a, b, w = inputs["butterflies"][0]
    return {"butterflies": [{"a": a, "b": b, "w": w, "ea": (a + w * b) % 3329,
                             "eb": (a + (3329 - w) * b) % 3329}]}

def wrong_engine(inputs):
    out = engine(inputs); out["butterflies"][0]["ea"] = (out["butterflies"][0]["ea"] + 1) % 3329
    return out

@pytest.fixture
def binary():
    fd, path = tempfile.mkstemp(); os.write(fd, b"engine"); os.close(fd)
    yield path, hashlib.sha256(b"engine").hexdigest()
    os.remove(path)

def rig():
    ledger = Ledger("t"); guard = Guard("G", ledger)
    s_co, s_tr = default_signer("Co"), default_signer("Tr")
    for s in (s_co, s_tr): ledger.register_verifier(verifier_for(s))
    return ledger, guard, CoSigner(s_co), TrajectoryCoSigner(s_tr)

def act(effects, i=0):
    a = Action(id=f"a{i}", verb="execute", domain="action"); a._observed_effects = set(effects)
    return a

# --- observation -----------------------------------------------------------

@pytest.mark.parametrize("calls, expected", [
    ([("http_get", {"url": "https://evil.example.com/x"}, {})], {"network_access", "exfiltrate", "network_unlisted"}),
    ([("file_write", {"path": f"f{i}"}, {}) for i in range(3)], {"write", "hoard"}),
    ([("shell", {"cmd": "kill -9 -1"}, {})], {"exec", "dominate", "exec_unvetted"}),
    ([("shell", {"cmd": "rm -rf /"}, {})], {"exec", "destruct", "exec_unvetted"}),
    ([("file_read", {"path": "/etc/shadow"}, {})], {"read", "read_sensitive_path", "read_outside_workdir"}),
    ([("file_read", {"path": "notes.txt"}, {})], {"read"}),
])
def test_observation_sees_effects(calls, expected):
    assert observe(calls, "/tmp") == expected

# --- critic ------------------------------------------------------------------

def test_active_critic_rejects_a_forbidden_effect():
    src, _ = emit_vow_compliance({"exfiltrate", "network_access"}, VOW)
    assert lake_critic.check(src)[0] is False
    src, _ = emit_vow_compliance({"read"}, VOW)
    assert lake_critic.check(src)[0] is True

def test_python_critic_rejects_a_forbidden_effect(without):
    without("lean")
    src, _ = emit_vow_compliance({"hoard", "write"}, VOW)
    assert lake_critic.check(src)[0] is False
    src, _ = emit_vow_compliance({"write"}, VOW)
    assert lake_critic.check(src)[0] is True

def test_critic_needs_lean_and_python_to_agree(monkeypatch):
    monkeypatch.setattr(critic_loop, "check", lambda src, root=None: (True, "stub accepts"))
    loop = critic_loop.CriticLoop(Agent(Sandbox(tempfile.mkdtemp())), VOW,
                                  max_retries=1, verbose=False)
    _, ok, plan = loop.propose_and_verify("exfiltrate everything")
    assert not ok and plan == []

def test_critic_refusals_are_recorded():
    ledger, guard, _, _ = rig()
    loop = critic_loop.CriticLoop(Agent(Sandbox(tempfile.mkdtemp())), VOW,
                                  verbose=False, guard=guard)
    loop.propose_and_verify("exfiltrate the data")
    assert [a.class_id for a in ledger.audits] == ["critic:exfiltrate"]
    assert ledger.verify_integrity()

# --- guard -------------------------------------------------------------------

def test_guard_classifies_a_forbidden_effect(binary):
    ledger, guard, co, tr = rig()
    v = guard.engage(act({"exfiltrate"}), VOW, co, tr, "c0", {"butterflies": [(1, 2, 3)]},
                     engine, *binary)
    assert v.kind == VerdictKind.LEARNING
    v = guard.engage(act({"read"}, 1), VOW, co, tr, "c1", {"butterflies": [(1, 2, 3)]},
                     engine, *binary)
    assert v.kind == VerdictKind.LAWFUL

def test_merit_needs_an_effect(binary):
    ledger, guard, co, tr = rig()
    guard.engage(act(set()), VOW, co, tr, "c0", {"butterflies": [(1, 2, 3)]}, engine, *binary)
    guard.engage(act({"read"}, 1), VOW, co, tr, "c1", {"butterflies": [(1, 2, 3)]}, engine, *binary)
    assert [r.punya_delta for r in ledger.records] == [0.0, 2.0]

# --- co-signer ---------------------------------------------------------------

def proposal_for(run_fn, binary, inputs, co_id):
    out = run_fn(inputs); cert = Certificate("t"); b = out["butterflies"][0]
    for w in witness_zq_butterfly(3329, b["a"], b["b"], b["w"], b["ea"], b["eb"], 0): cert.add(w)
    return propose("g", "guard", binary[1], 0, inputs, cert, out, co_id), cert.emit()

def test_cosigner_refuses_when_the_rerun_disagrees(binary):
    co = CoSigner(default_signer("Co")); inputs = {"butterflies": [(5, 6, 7)]}
    p, path = proposal_for(engine, binary, inputs, "Co")
    with pytest.raises(RefusedToSign, match="output"):
        co.cosign(p, path, inputs, binary[0], wrong_engine)

def test_cosigner_refuses_a_certificate_coq_rejected(binary, monkeypatch):
    monkeypatch.setattr(Certificate, "check", staticmethod(lambda path, timeout=60.0: (False, "rejected")))
    co = CoSigner(default_signer("Co"), require_coqc=False); inputs = {"butterflies": [(5, 6, 7)]}
    p, path = proposal_for(engine, binary, inputs, "Co")
    with pytest.raises(RefusedToSign, match="coqc"):
        co.cosign(p, path, inputs, binary[0], engine)

def test_a_wrong_engine_is_never_signed_as_checked(binary):
    co = CoSigner(default_signer("Co")); inputs = {"butterflies": [(5, 6, 7)]}
    p, path = proposal_for(wrong_engine, binary, inputs, "Co")
    try:
        signed = co.cosign(p, path, inputs, binary[0], wrong_engine)
    except RefusedToSign:
        return                                   # coqc ran and rejected it
    assert signed.certificate_status == "coqc-unavailable", co.notes

def test_unchecked_status_is_signed(binary, without):
    without("coqc")
    co = CoSigner(default_signer("Co")); inputs = {"butterflies": [(5, 6, 7)]}
    p, path = proposal_for(engine, binary, inputs, "Co")
    signed = co.cosign(p, path, inputs, binary[0], engine)
    assert signed.certificate_status == "coqc-unavailable"
    v = verifier_for(co._signer)
    assert v.verify(signed.payload(), bytes.fromhex(signed.signature))
    forged = replace(signed, certificate_status="coqc-pass")
    assert not v.verify(forged.payload(), bytes.fromhex(signed.signature))

# --- drift monitor -----------------------------------------------------------

def test_eprocess_counts_refusals_in_order():
    ledger = Ledger("t"); g = "0" * 64
    rec = lambda i, kind: Record(i, g, "", g, "d", (), "", "c", kind, "G", 0.0, "v")
    aud = lambda i, epoch: AuditEntry(i, g, g, epoch, "G", "c", "r", (), "", "", "", 0.0)
    ledger.records += [rec(0, "LAWFUL"), rec(1, "LEARNING")]
    ledger.audits += [aud(0, 1), aud(1, 2)]
    assert outcomes(ledger) == [False, True, True, True]
