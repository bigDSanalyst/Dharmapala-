"""The capture latch (Phase 2, slice 4b; docs/monitor-boundary.md, section 5).

On a protocol violation, or a failure of its own, the monitor (P0) is
captured, for good: it closes every descriptor into the workdir, restricts
itself with Landlock to its quarantine stream alone, records the capture
and signs the terminal checkpoint, and refuses every call after. Landlock is
for good, so the latch's own test captures a process of its own."""
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
import guarded_agent as ga
import monitor
from tests.test_jail import needs_jail


CAPTURED = r'''
import json, os, subprocess, sys
sys.path.insert(0, sys.argv[3])
import jail, monitor
from signing import default_signer
from tools import Sandbox
W, Q = sys.argv[1], sys.argv[2]
mon = monitor.Monitor(default_signer("Monitor"), W, quarantine=Q)
real = mon.header["workdir"]
spaces = {"real": (None, Sandbox(real, jail=True, monitor=mon, parse_trace=False))}
before = {"write": spaces["real"][1].file_write("a.txt", "alpha")["ok"], "jail": jail.available()[0]}
held = spaces["real"][1]._vfs._root_fd       # the workdir's pinned descriptor: Landlock would not revoke it
before["held"] = sorted(os.listdir(held))
extra = os.open(real, os.O_RDONLY | os.O_DIRECTORY)   # one opened elsewhere, which no space knows of
rec, cp, confined = monitor.capture(mon, spaces, "ipc", "not JSON", "not json")
after = {}
def attempt(name, fn):
    try: fn(); after[name] = "done"
    except OSError: after[name] = "refused"
attempt("open the workdir", lambda: os.close(os.open(real, os.O_RDONLY | os.O_DIRECTORY)))
attempt("list it", lambda: os.listdir(real))
attempt("list it through the descriptor it held", lambda: os.listdir(held))
attempt("list it through one opened elsewhere", lambda: os.listdir(extra))
attempt("read a file in it", lambda: open(os.path.join(real, "a.txt")).read())
attempt("through /proc/self/root", lambda: open("/proc/self/root" + real + "/a.txt").read())
attempt("write in it", lambda: open(os.path.join(real, "b.txt"), "w").close())
attempt("execute bwrap", lambda: subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], capture_output=True))
after["start a jail"] = "done" if jail.available()[0] else "refused"
records, checkpoint = monitor.load_quarantine(os.path.join(Q, mon.session))
monitor.check_quarantine(records, checkpoint, mon.verifier, mon.session)
print(json.dumps({"before": before, "after": after, "confined": confined, "spaces": len(spaces),
                  "terminal": [records[-1]["terminal_mode"], records[-1]["trigger"]["layer"],
                               checkpoint["terminal_mode"]]}))
'''

@needs_jail
def test_after_a_tripwire_the_monitor_can_neither_open_the_workdir_nor_start_a_jail(tmp_path):
    """Phase 2's exit criterion. Before, the monitor writes in the workdir and
    a jail works; after, every way in is refused, and the capture is in its
    signed stream."""
    work = tmp_path / "work"
    r = subprocess.run([sys.executable, "-c", CAPTURED, str(work), str(tmp_path / "q"), str(ROOT)],
                       capture_output=True, text=True, timeout=120, cwd=str(ROOT),
                       env=dict(os.environ, TMPDIR=str(tmp_path)))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["before"] == {"write": True, "jail": True, "held": ["a.txt"]}
    assert set(out["after"].values()) == {"refused"}, out["after"]
    assert out["confined"] and out["spaces"] == 0
    assert out["terminal"] == ["captured", "ipc", "captured"]
    assert (work / "a.txt").read_text() == "alpha" and not (work / "b.txt").exists()


def _violate(m):
    bad = b"not json"
    m._sock.sendall(struct.pack(">I", len(bad)) + bad)

@pytest.mark.parametrize("on_disk", [True, False], ids=["stream on disk", "stream in memory"])
def test_a_protocol_violation_captures_the_monitor(tmp_path, on_disk):
    m = monitor.RemoteMonitor(tmp_path / "work", quarantine=(tmp_path / "q") if on_disk else None)
    try:
        assert m.call("file_write", space="real", path="a.txt", content="x")["result"]["ok"]
        _violate(m)
        for _ in range(3):                                     # nothing runs, however often it is asked
            with pytest.raises(monitor.MonitorCaptured, match="a protocol violation: not JSON"):
                m.call("file_write", space="real", path="b.txt", content="y")
        last = m.quarantine_records[-1]
        assert (last["terminal_mode"], last["trigger"]["layer"]) == ("captured", "ipc")
        assert m.quarantine_checkpoint["terminal_mode"] == "captured"
        monitor.check_quarantine(m.quarantine_records, m.quarantine_checkpoint, m.verifier, m.session)
        if on_disk:
            records, checkpoint = monitor.load_quarantine(tmp_path / "q" / m.session)
            assert records == m.quarantine_records and checkpoint == m.quarantine_checkpoint
    finally:
        m.close()
    assert m._proc.returncode == monitor.PROTOCOL_EXIT
    assert not (tmp_path / "work" / "b.txt").exists()


def test_a_monitor_that_cannot_keep_its_stream_stops_at_once(tmp_path):
    """A refusal it cannot record is a failure of its own: it is captured,
    and since it cannot record that either, it stops rather than go on."""
    m = monitor.RemoteMonitor(tmp_path / "work", quarantine=tmp_path / "q")
    try:
        shutil.rmtree(tmp_path / "q" / m.session)
        with pytest.raises(monitor.MonitorCaptured, match="a failure of its own"):
            m.call("file_read", space="real", path="../outside")     # a refusal it must record
        assert m._proc.wait(timeout=10) == monitor.INVARIANT_EXIT
    finally:
        m.close()


@needs_jail
def test_the_gate_refuses_every_call_once_the_monitor_is_captured(tmp_path):
    gate, _ = ga.setup(tmp_path / "w", quarantine=tmp_path / "q")
    _violate(gate.monitor)
    for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "x"}),
                                      ("shell", {"cmd": "echo hi > b.txt"}),
                                      ("file_read", {"path": "a.txt"})]):
        detail, error = gate.run(f"c{i}", tool, args)
        assert error and "the monitor is captured" in detail and gate.log[-1][2] == "refused", detail
    assert os.listdir(tmp_path / "w") == []
