"""The co-signers as their own process (Phase 3, slice 1; docs/monitor-boundary.md, P2).

The co-signer and the trajectory co-signer, with the keys every attestation
in the ledger rests on, run in a process of their own (cosigner.py), started
by the gate before it confines itself: undumpable, serving only its parent,
with a replay monitor of its own as its child. The gate, which parses
everything untrusted, holds their public keys and nothing else."""
import ctypes
import gc
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
import cosigner
import guarded_agent as ga
import monitor
import runs
import signing
from tests.test_jail import needs_jail
from to_coq_witness import ConfigError, RefusedToSign, propose, build_certificate

SECRETS = (signing.MLDSASigner, signing.HMACSigner, signing.SharedSecretVerifier)
TRAJECTORY_VOW = ga.DEFAULT_VOW + "  trajectory no_write_after_read: never verb:file_write after verb:file_read\n"

def _secrets_held():
    gc.collect()
    return sorted((type(o).__name__, getattr(o, "id", "?")) for o in gc.get_objects() if isinstance(o, SECRETS))


@needs_jail
def test_the_gate_holds_no_key_material(tmp_path):
    """Phase 3's exit criterion: after a session (a write, a jailed shell call
    the co-signer replays, a read), nothing in the gate's process can sign."""
    gate, L = ga.setup(tmp_path / "work")
    for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "alpha"}),
                                      ("shell", {"cmd": "cat a.txt > b.txt"}),
                                      ("file_read", {"path": "b.txt"})]):
        detail, error = gate.run(f"c{i}", tool, args)
        assert not error, detail
        if tool == "shell": assert "re-execution: match" in gate.co_signer.notes   # replayed, in P2
    assert runs.verify(gate.runs.entries, L) == [] and L.verify_integrity()
    assert _secrets_held() == []
    assert all(isinstance(v, signing.PublicVerifier) for v in L.verifiers.values())

def test_without_ml_dsa_the_keys_stay_here_and_the_check_says_so(tmp_path, without):
    """The check above can see keys: with no publicly verifiable scheme, the
    co-signers stay in the gate's process under HMAC keys, and it finds them."""
    without("dilithium-py")
    gate, _ = ga.setup(tmp_path / "work")
    assert not isinstance(gate.co_signer, cosigner.RemoteCoSigner)
    held = _secrets_held()
    assert ("HMACSigner", "CoSigner") in held and ("HMACSigner", "Trajectory") in held


def test_the_co_signers_are_their_own_process_and_the_ledger_holds_their_public_keys(tmp_path):
    gate, L = ga.setup(tmp_path / "work")
    p2 = gate.co_signer._proc
    assert isinstance(gate.co_signer, cosigner.RemoteCoSigner) and gate.traj_cosigner._proc is p2
    assert p2.pid not in (os.getpid(), gate.monitor.pid)
    for name, remote in (("CoSigner", gate.co_signer), ("Trajectory", gate.traj_cosigner)):
        assert L.verifiers[name].key_id() == remote.verifier.key_id()
        assert not hasattr(remote, "_signer")


@pytest.mark.skipif(os.getuid() == 0, reason="root may read any process's memory")
def test_a_process_of_the_same_user_cannot_read_the_co_signers_memory(tmp_path):
    gate, _ = ga.setup(tmp_path / "work")
    pid = gate.co_signer._proc.pid
    for name in ("mem", "environ"):
        with pytest.raises(PermissionError):
            open(f"/proc/{pid}/{name}", "rb").read(1)
    libc = ctypes.CDLL(None, use_errno=True)
    PTRACE_ATTACH = 16
    assert libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1


def test_the_co_signer_refuses_a_peer_that_is_not_its_parent(tmp_path):
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    inner = [sys.executable, "-E", "-s", str(ROOT / "cosigner.py"), "serve", str(theirs.fileno()),
             str(tmp_path / "work"), "{}", "ml-dsa-65", "00"]
    middle = subprocess.run([sys.executable, "-c", "import subprocess, sys; sys.exit(subprocess.call("
                             f"{inner!r}, pass_fds=[{theirs.fileno()}]))"],
                            pass_fds=[theirs.fileno()], capture_output=True, text=True, timeout=60)
    theirs.close(); ours.settimeout(10)
    assert middle.returncode == 1 and "refusing peer" in middle.stderr
    assert ours.recv(4) == b""                                    # no hello, nothing signed


def _frame(payload):
    return struct.pack(">I", len(payload)) + payload

@pytest.mark.parametrize("frame", [
    _frame(b"not json"),
    _frame(monitor.canon({"v": 1, "seq": 0, "op": "sign", "args": {"payload": "x"}}).encode()),
    _frame(monitor.canon({"v": 1, "seq": 0, "op": "release", "args": {"handle": 3}}).encode()),
    _frame(monitor.canon({"v": 1, "seq": 0, "op": "cosign", "args": {"proposal": {"x": 1}, "inputs": {},
                                                                     "decision": None, "evidence": None,
                                                                     "snapshot": None}}).encode()),
    _frame(monitor.canon({"v": 1, "seq": 1, "op": "snapshot", "args": {}}).encode()),
    _frame(monitor.canon({"v": 1, "seq": 0, "op": "observe", "args": {"evidence": "a run"}}).encode()),
], ids=["not-json", "unknown-op", "bad-handle", "not-an-attestation", "out-of-sequence", "not-a-run-record"])
def test_a_request_that_is_not_exactly_a_known_operation_ends_the_co_signer(tmp_path, frame):
    """And with it every attestation: the gate runs nothing more, and nothing
    is signed or stored."""
    gate, L = ga.setup(tmp_path / "work")
    p2 = gate.co_signer._proc
    p2._sock.sendall(frame)
    assert p2._proc.wait(timeout=30) == cosigner.PROTOCOL_EXIT
    before = len(L.attestations)
    detail, error = gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})
    assert error and "nothing more runs in this session" in detail
    assert len(L.attestations) == before and not (tmp_path / "work" / "a.txt").exists()


def test_once_the_co_signers_are_gone_nothing_more_runs(tmp_path):
    """As with a monitor that is gone: nothing could be signed, so nothing runs.
    Asked anyway, neither co-signer vouches, and the call is not checked."""
    gate, L = ga.setup(tmp_path / "work", vow_source=TRAJECTORY_VOW)
    p2 = gate.co_signer._proc
    os.kill(p2.pid, signal.SIGKILL); p2._proc.wait(timeout=30)
    before = len(L.attestations)
    for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "x"}),
                                      ("shell", {"cmd": "echo hi > b.txt"}), ("file_read", {"path": "a.txt"})]):
        detail, error = gate.run(f"c{i}", tool, args)
        assert error and "the co-signer process is gone" in detail and "nothing more runs" in detail, detail
    assert not any((tmp_path / "work").iterdir()) and len(L.attestations) == before
    proposal, d = _proposal_for(gate, gate.binary_hash, ga._engine({}))
    with pytest.raises(ConfigError, match="not checked"):
        gate.co_signer.cosign(proposal, "", {"tool_use_id": "c0"}, gate.binary_path, ga._engine, decision=d)
    assert gate.co_signer.notes == ["co-signer: GONE"]
    ok, why = gate.traj_cosigner.cosign(gate.vow.trajectories(), (), _an_action(), "LAWFUL")
    assert not ok and "gone" in why


@needs_jail
def test_without_its_replay_monitor_the_co_signer_lets_no_shell_call_run(tmp_path):
    """It could not replay one, so it could not vouch for one: nothing runs.
    A file call needs no replay and is still checked."""
    gate, L = ga.setup(tmp_path / "work")
    p2 = gate.co_signer._proc
    os.kill(p2.replay_monitor_pid, signal.SIGKILL)
    detail, error = gate.run("c0", "shell", {"cmd": "echo hi > a.txt"})
    assert error and "its replay monitor is gone" in detail and "nothing ran" in detail, detail
    assert not (tmp_path / "work" / "a.txt").exists() and p2._proc.poll() is None
    detail, error = gate.run("c1", "file_write", {"path": "b.txt", "content": "x"})
    assert not error, detail


@pytest.mark.parametrize("op", ["cosign", "traj_cosign"])
@pytest.mark.parametrize("answer", ["another call's", "not signed by its key"])
def test_the_gate_takes_only_a_signed_answer_to_what_it_asked(tmp_path, monkeypatch, op, answer):
    """Each attestation must verify under the key from the hello, and be for
    the proposal or the action it was sent: an answer about another call,
    though signed, is not taken."""
    gate, L = ga.setup(tmp_path / "work", vow_source=TRAJECTORY_VOW if op == "traj_cosign" else ga.DEFAULT_VOW)
    p2, kept = gate.co_signer._proc, {}
    real = p2.call
    def tampered(o, **args):
        r = real(o, **args)
        if o != op: return r
        if answer == "another call's": return kept.setdefault(o, r)        # every answer is the first one's
        r = json.loads(json.dumps(r)); sig = r["attestation"]["signature"]
        r["attestation"]["signature"] = ("1" if sig[0] == "0" else "0") + sig[1:]
        return r
    monkeypatch.setattr(p2, "call", tampered)
    if answer == "another call's":
        assert not gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})[1]
    before = len(L.attestations)
    detail, error = gate.run("c1", "file_write", {"path": "b.txt", "content": "y"})
    assert error and "withheld" in detail, detail
    assert ("not for the" if answer == "another call's" else "does not verify under its key") in detail, detail
    assert len(L.attestations) == before


def test_a_co_signer_that_does_not_answer_in_time_is_not_asked_again(tmp_path):
    """Its late answer would be read as the answer to the next request, so the
    gate asks nothing more, though the process is still there."""
    gate, L = ga.setup(tmp_path / "work")
    p2 = gate.co_signer._proc
    p2._sock.settimeout(0.001)
    detail, error = gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})
    assert error and "not checked" in detail and "withheld" in detail, detail
    p2._sock.settimeout(60)
    assert p2._proc.poll() is None
    before = len(L.attestations)
    detail, error = gate.run("c1", "file_write", {"path": "b.txt", "content": "y"})
    assert error and "nothing more runs in this session" in detail, detail
    assert not (tmp_path / "work" / "b.txt").exists() and len(L.attestations) == before


def _an_action():
    from vow import Action
    a = Action(id="c0", verb="file_write", domain="action"); a._observed_effects = set()
    return a

def _proposal_for(gate, binary_hash, outputs):
    from decision import Decision
    from vow import Action
    a = Action(id="c0", verb="http_get", domain="action"); a._observed_effects = set()
    d = Decision.of(a, gate.vow)
    cert = build_certificate("Guard_0", outputs, d)
    return propose("Guard", "guard", binary_hash, 0, {"tool_use_id": "c0"}, cert, outputs,
                   gate.co_signer.id, decision=d), d

@pytest.mark.parametrize("what", ["binary", "engine"])
def test_the_gate_cannot_choose_the_binary_or_the_engine(tmp_path, what):
    """The co-signer hashes its own binary and runs its own engine: a gate that
    names another binary, or claims another engine's output, is refused."""
    gate, _ = ga.setup(tmp_path / "work")
    if what == "binary":
        other = hashlib.sha256(open("/bin/sh", "rb").read()).hexdigest()
        proposal, d = _proposal_for(gate, other, ga._engine({}))
        with pytest.raises(RefusedToSign, match="binary mismatch"):
            gate.co_signer.cosign(proposal, "", {"tool_use_id": "c0"}, "/bin/sh", lambda i: {}, decision=d)
    else:
        claimed = {"butterflies": [], "and": "more"}             # not what its engine gives
        proposal, d = _proposal_for(gate, gate.binary_hash, claimed)
        with pytest.raises(RefusedToSign, match="output mismatch"):
            gate.co_signer.cosign(proposal, "", {"tool_use_id": "c0"}, gate.binary_path, lambda i: claimed,
                                  decision=d)


@needs_jail
def test_a_snapshot_stays_with_the_co_signer(tmp_path, monkeypatch):
    """The gate holds a handle, not a copy. One the co-signer never gave names
    no snapshot, even while it holds one, and the run is not signed."""
    gate, _ = ga.setup(tmp_path / "work")
    handle = gate.co_signer.snapshot(gate.workdir)
    assert isinstance(handle, str) and not os.path.exists(handle)
    monkeypatch.setattr(gate.co_signer, "snapshot", lambda workdir: "snap999")
    detail, error = gate.run("c0", "shell", {"cmd": "echo hi > a.txt"})
    assert error and "withheld" in detail and "re-execution: NO SNAPSHOT" in gate.co_signer.notes
    gate.co_signer.release(handle)


def test_the_trajectory_co_signer_signs_from_its_process(tmp_path):
    gate, L = ga.setup(tmp_path / "work", vow_source=TRAJECTORY_VOW)
    outcomes = []
    for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "x"}),
                                      ("file_read", {"path": "a.txt"}),
                                      ("file_write", {"path": "b.txt", "content": "y"})]):
        gate.run(f"c{i}", tool, args)
        outcomes.append(gate.log[-1][2])
    assert outcomes == ["lawful", "lawful", "learning"]                       # a write after a read
    signed = [a for a in L.attestations.values() if a.signer_id == "Trajectory"]
    assert len(signed) == 3 and L.verify_integrity()
    assert all(gate.traj_cosigner.verifier.verify(a.payload(), bytes.fromhex(a.signature)) for a in signed)
