"""The monitor as its own process (Phase 2, slice 2; docs/monitor-boundary.md).

The gate (P1) parses everything untrusted; the monitor (P0) holds the key
and the workdir's descriptor and runs every real call. Here they are two
processes: P0 is started by the gate on a socketpair, makes itself
undumpable, refuses any peer but its parent, and closes the connection on the
first request that is not exactly a known operation. The gate holds only the
monitor's public key, and refuses every call once the monitor is gone."""
import ctypes
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
import guarded_agent as ga
import monitor
import runs
from tests.test_jail import needs_jail


@pytest.fixture
def remote(tmp_path):
    m = monitor.RemoteMonitor(tmp_path / "work")
    yield m
    m.close()


def test_the_monitor_is_its_own_process_and_the_gate_holds_no_key(tmp_path):
    gate, L = ga.setup(tmp_path / "work")
    m = gate.monitor
    assert isinstance(m, monitor.RemoteMonitor) and m.pid != os.getpid()
    assert not hasattr(m, "_signer") and m.verifier.scheme == "ml-dsa-65"
    assert L.verifiers["Monitor"].key_id() == m.verifier.key_id() == m.header["monitor_key_id"]


@pytest.mark.skipif(os.getuid() == 0, reason="root may read any process's memory")
def test_a_process_of_the_same_user_cannot_read_the_monitors_memory(remote):
    for name in ("mem", "environ"):
        with pytest.raises(PermissionError):
            open(f"/proc/{remote.pid}/{name}", "rb").read(1)
    libc = ctypes.CDLL(None, use_errno=True)
    PTRACE_ATTACH = 16
    assert libc.ptrace(PTRACE_ATTACH, remote.pid, None, None) == -1


@needs_jail
def test_a_session_through_the_monitor_process_verifies(tmp_path):
    gate, L = ga.setup(tmp_path / "work")
    for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "hi"}),
                                      ("file_read", {"path": "a.txt"}),
                                      ("shell", {"cmd": "cat a.txt"})]):
        _, error = gate.run(f"c{i}", tool, args)
        assert not error and "session: signed, chained, witnesses bound to its root" in gate.co_signer.notes
    assert runs.verify(gate.runs.entries, L) == []
    assert {e["session"]["header"]["session"] for e in gate.runs.entries} == {gate.monitor.session}


@needs_jail
def test_the_gate_reads_the_trace_the_monitor_returns(tmp_path):
    """The monitor returns the raw trace unread; the events the guard judges
    are the gate's own reading of it (jail.parse), as the co-signer's are its."""
    gate, _ = ga.setup(tmp_path / "work")
    _, error = gate.run("c0", "shell", {"cmd": "python3 -c \"open('b.txt', 'w').write('x')\""})
    assert not error
    tool, kwargs, result = gate.runs.entries[-1]["evidence"]["calls"][0]
    target = os.path.realpath(tmp_path / "work" / "b.txt")
    assert ["write", target, True] in result["events"]
    assert "events" not in json.dumps(gate.runs.entries[-1]["session"])   # not in what the monitor signed


@needs_jail
def test_a_trace_larger_than_a_seqpacket_message_crosses_the_boundary(tmp_path):
    gate, L = ga.setup(tmp_path / "work")
    _, error = gate.run("c0", "shell", {"cmd": "for i in $(seq 2500); do : > f$i; done"})
    assert not error
    trace = gate.runs.entries[-1]["evidence"]["calls"][0][2]["trace"]
    assert len(json.dumps(trace)) > 212992                        # SOCK_SEQPACKET's default cap
    assert runs.verify(gate.runs.entries, L) == []


def _frame(payload):
    return struct.pack(">I", len(payload)) + payload

def _req(**over):
    r = {"v": 1, "seq": 0, "op": "http_get", "args": {"url": "https://example.org/"}}
    r.update(over)
    return monitor.canon(r).encode()

@pytest.mark.parametrize("frame", [
    _frame(b"not json"),
    _frame(b'{"args": {"url": "https://example.org/"}, "op": "http_get", "seq": 0, "v": 1}'),  # not canonical
    _frame(_req(op="__init__", args={"workdir": "/"})),
    _frame(_req(args={"url": "https://example.org/", "extra": "x"})),
    _frame(_req(args={})),
    _frame(_req(args={"url": 3})),
    _frame(_req(seq=1)),
    _frame(_req(seq=True)),
    _frame(_req(v=2)),
    struct.pack(">I", monitor.MAX_REQUEST + 1),                    # refused before its payload arrives
], ids=["not-json", "not-canonical", "unknown-op", "extra-arg", "missing-arg", "not-a-string",
        "out-of-sequence", "bool-seq", "wrong-version", "oversize"])
def test_a_request_that_is_not_exactly_a_known_operation_ends_the_monitor(remote, frame):
    remote._sock.sendall(frame)
    assert remote._proc.wait(timeout=10) == monitor.PROTOCOL_EXIT
    with pytest.raises(monitor.MonitorGone):
        remote.call("http_get", url="https://example.org/")


def test_a_well_formed_request_is_answered_and_recorded(remote):
    r = remote.call("http_get", url="https://example.org/")
    assert r["result"]["sandbox"] is True and r["record"]["index"] == 0
    block = remote.end_run()
    monitor.check_block(block, remote.verifier, remote.workdir)


@needs_jail
def test_the_gate_refuses_every_call_once_the_monitor_is_gone(tmp_path):
    gate, _ = ga.setup(tmp_path / "work")
    os.kill(gate.monitor.pid, signal.SIGKILL); gate.monitor._proc.wait()
    for i in range(2):
        detail, error = gate.run(f"c{i}", "file_write", {"path": "a.txt", "content": "x"})
        assert error and "monitor process is gone" in detail and gate.log[-1][2] == "refused"
    assert not (tmp_path / "work" / "a.txt").exists()


def test_the_monitor_refuses_a_peer_that_is_not_its_parent(tmp_path):
    """The socketpair is ours, but the monitor's parent is a process in
    between: SO_PEERCRED names us, so it refuses to serve."""
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    inner = [sys.executable, "-E", "-s", str(ROOT / "monitor.py"), "serve", str(theirs.fileno()),
             str(tmp_path / "work"), "", ""]
    middle = subprocess.run([sys.executable, "-c", "import subprocess, sys; sys.exit(subprocess.call("
                             f"{inner!r}, pass_fds=[{theirs.fileno()}]))"],
                            pass_fds=[theirs.fileno()], capture_output=True, text=True, timeout=60)
    theirs.close(); ours.settimeout(10)
    assert middle.returncode == 1 and "refusing peer" in middle.stderr
    assert ours.recv(4) == b""                                    # no hello, nothing served


def test_without_ml_dsa_the_monitor_stays_in_this_process(tmp_path, without):
    without("dilithium-py")
    m = monitor.start(tmp_path / "work")
    assert isinstance(m, monitor.Monitor) and m.verifier.scheme == "hmac-sha256"
