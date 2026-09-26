"""A toolchain that hangs or will not run has not judged anything.

Before this, a hung coqc read as "Coq rejected the certificate", so the
co-signer refused a correct certificate and the refusal was recorded against
the action, and a hung Lean read as "the critic rejected the plan", recorded
against the agent. Both put the machine's failure into the record as a
verdict. Each test puts a real stand-in for the tool on the path."""
import hashlib, os, stat, tempfile

import pytest

import tests.support  # noqa: F401
import critic_loop, lake_critic, to_coq_witness
from agent import Agent
from decision import Decision
from guard import Guard, VerdictKind
from ledger import Ledger
from signing import default_signer, verifier_for
from to_coq_witness import (Certificate, ConfigError, CoSigner, build_certificate, propose)
from tools import Sandbox
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

VOW = parse_vow("vow T\n  forbid exfiltrate forall action\n")

def stand_in(tmp_path, name, body):
    p = tmp_path / name; p.write_text(body); p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p

@pytest.fixture
def hung_coqc(tmp_path, monkeypatch):
    stand_in(tmp_path, "coqc", "#!/bin/sh\nsleep 30\n")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(to_coq_witness, "COQC_TIMEOUT", 1.0)

@pytest.fixture
def broken_coqc(tmp_path, monkeypatch):
    stand_in(tmp_path, "coqc", "#!/nonexistent/interpreter\n")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

@pytest.fixture
def binary():
    fd, path = tempfile.mkstemp(); os.write(fd, b"engine"); os.close(fd)
    yield path, hashlib.sha256(b"engine").hexdigest()
    os.remove(path)

def engine(inputs):
    a, b, w = inputs["butterflies"][0]
    return {"butterflies": [{"a": a, "b": b, "w": w, "ea": (a + w * b) % 3329,
                             "eb": (a + (3329 - w) * b) % 3329}]}

INPUTS = {"butterflies": [(1, 2, 3)]}

def act(effects):
    a = Action(id="a", verb="execute", domain="action"); a._observed_effects = set(effects); return a

@pytest.mark.parametrize("fault", ["hung_coqc", "broken_coqc"])
def test_a_coqc_that_did_not_run_checked_nothing(request, fault):
    request.getfixturevalue(fault)
    ok, why = Certificate.check(Certificate("t").emit())
    assert ok is None, why

@pytest.mark.parametrize("fault", ["hung_coqc", "broken_coqc"])
def test_the_cosigner_signs_unchecked_not_refused(request, fault, binary):
    request.getfixturevalue(fault)
    L = Ledger("t"); g = Guard("G", L)
    s_co, s_tr = default_signer("Co"), default_signer("Tr")
    for s in (s_co, s_tr): L.register_verifier(verifier_for(s))
    v = g.engage(act({"read"}), VOW, CoSigner(s_co), TrajectoryCoSigner(s_tr), "c0", INPUTS, engine, *binary)
    assert v.kind == VerdictKind.LAWFUL and not L.audits
    assert L.attestations[v.attestation_hash].certificate_status == "coqc-unavailable"

def test_a_hung_coqc_is_a_config_error_when_coq_is_required(hung_coqc, binary):
    co = CoSigner(default_signer("Co"), require_coqc=True)
    d = Decision.of(act({"read"}), VOW); cert = build_certificate("x", engine(INPUTS), d)
    p = propose("g", "guard", binary[1], 0, INPUTS, cert, engine(INPUTS), "Co", decision=d)
    with pytest.raises(ConfigError, match="timed out"):
        co.cosign(p, cert.emit(), INPUTS, binary[0], engine, decision=d)

@pytest.fixture
def hung_lean(tmp_path, monkeypatch):
    lean = stand_in(tmp_path, "lean", '#!/bin/sh\n[ "$1" = "--version" ] && { echo "Lean (version 4.14.0)"; exit 0; }\nsleep 30\n')
    monkeypatch.setattr(lake_critic, "_LEAN", str(lean))
    monkeypatch.setattr(lake_critic, "LEAN_TIMEOUT", 1.0)

def test_a_hung_lean_checked_nothing(hung_lean):
    assert lake_critic.check("example : True := trivial")[0] is None

def test_a_hung_critic_accepts_nothing_and_blames_no_one(hung_lean):
    L = Ledger("t"); g = Guard("G", L)
    loop = critic_loop.CriticLoop(Agent(Sandbox(tempfile.mkdtemp())), VOW, verbose=False, guard=g)
    effects, ok, plan = loop.propose_and_verify("read /etc/hostname")
    assert (ok, plan) == (False, [])
    assert loop.unchecked == 1 and L.audits == []

def test_the_demo_does_not_count_a_hung_lean_as_run(hung_lean):
    import run_demo
    res = run_demo.main()
    assert not res["ok"] and "lean critic" in res["missing"]
