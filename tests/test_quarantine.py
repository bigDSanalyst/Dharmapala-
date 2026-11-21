"""The quarantine stream (Phase 2, slice 4a; docs/monitor-boundary.md, section 5).

What was refused in a session goes to a stream of its own, which the monitor
(P0) keeps apart from the session's record: its own cw_vfs refusals, and the
Vow and guard refusals the gate reports. It parses none of it; it clips,
hashes and chains it, and signs a checkpoint over the head at every append.
The session stays live: a refusal is recorded, and the next call runs."""
import hashlib
import json
import os

import pytest

import tests.support  # noqa: F401
import guarded_agent as ga
import monitor
from signing import default_signer
from tests.test_jail import needs_jail


@pytest.fixture
def remote(tmp_path):
    m = monitor.RemoteMonitor(tmp_path / "work", quarantine=tmp_path / "q")
    yield m
    m.close()

def _stream(m, root):
    """The stream as the monitor wrote it, checked against its key."""
    records, checkpoint = monitor.load_quarantine(os.path.join(root, m.session))
    monitor.check_quarantine(records, checkpoint, m.verifier, m.session)
    return records, checkpoint


def test_a_refused_call_appears_in_the_quarantine_stream(remote, tmp_path):
    """Phase 2's exit criterion: the monitor refuses a call, records it, signs
    it, and the session goes on."""
    refused = remote.call("file_read", space="real", path="../outside")
    assert refused["result"]["ok"] is False and refused["quarantine"]["record"] is not None
    then = remote.call("file_write", space="real", path="a.txt", content="alpha")
    assert then["result"]["ok"] and "quarantine" not in then                  # still live, and lawful
    [rec], checkpoint = _stream(remote, tmp_path / "q")
    assert rec["trigger"]["layer"] == "cw_vfs" and rec["trigger"]["reason"] == "EXDEV"
    assert rec["trigger"]["record_index"] == refused["record"]["index"]          # the call's session record
    assert json.loads(rec["trigger"]["call_json"]) == {"op": "file_read", "args": {"path": "../outside"}}
    assert rec["terminal_mode"] == checkpoint["terminal_mode"] == "live"
    assert [rec] == remote.quarantine_records and checkpoint == remote.quarantine_checkpoint
    assert (tmp_path / "work" / "a.txt").read_text() == "alpha"


def test_every_file_call_cw_vfs_refuses_is_recorded(remote, tmp_path):
    """A missing file, a ../ path and an absolute path outside the workdir
    all come back as cw_vfs refusals (decision 5), each with its errno."""
    (tmp_path / "work").mkdir(exist_ok=True)
    for tool, args in [("file_read", {"path": "../x"}), ("file_read", {"path": "/etc/hostname"}),
                       ("file_read", {"path": "missing.txt"}), ("file_read", {"path": ""}),
                       ("file_write", {"path": "../x", "content": "x"})]:
        remote.call(tool, space="real", **args)
    records, _ = _stream(remote, tmp_path / "q")
    assert [(r["trigger"]["layer"], r["trigger"]["reason"]) for r in records] == \
        [("cw_vfs", "EXDEV"), ("cw_vfs", "EXDEV"), ("cw_vfs", "ENOENT"), ("cw_vfs", "EINVAL"), ("cw_vfs", "EXDEV")]
    assert [r["trigger"]["record_index"] for r in records] == [0, 1, 2, 3, 4]


def test_a_session_with_nothing_refused_has_an_empty_signed_stream(remote, tmp_path):
    """So a clean run verifies as one, rather than as a stream gone missing."""
    remote.call("file_write", space="real", path="a.txt", content="x")
    records, checkpoint = _stream(remote, tmp_path / "q")
    assert records == [] and (checkpoint["q_index"], checkpoint["head"]) == (-1, monitor.GENESIS)


def test_a_refusal_adds_nothing_to_the_session_record(remote):
    before = len(remote.call("checkpoint")["block"]["records"])
    remote.report_refusal("vow", "forbidden:network_unlisted", monitor.canon({"op": "http_get", "args": {}}))
    block = remote.call("checkpoint")["block"]
    assert before == 0 and block["records"] == [] and len(remote.quarantine_records) == 1


def test_the_gate_reports_the_vow_refusals_it_decides(tmp_path):
    gate, _ = ga.setup(tmp_path / "w", quarantine=tmp_path / "q")
    for i, (tool, args) in enumerate([("file_write", {"path": "/etc/dharma_x", "content": "x"}),
                                      ("http_get", {"url": "https://example.org/"})]):
        gate.run(f"c{i}", tool, args)
        assert gate.log[-1][2] == "refused"
    records, _ = _stream(gate.monitor, tmp_path / "q")
    assert [(r["trigger"]["layer"], r["trigger"]["reason"], r["trigger"]["record_index"]) for r in records] == \
        [("vow", "forbidden:write_outside_workdir", None), ("vow", "forbidden:network_unlisted", None)]
    assert json.loads(records[1]["trigger"]["call_json"]) == {"op": "http_get", "args": {"url": "https://example.org/"}}


@needs_jail
def test_the_gate_reports_a_run_the_guard_withheld(tmp_path):
    """A command that does what its rehearsal did not (diverged): it ran, the
    guard withheld its output, and the gate reports the verdict."""
    script = ('m=$(while read -r l; do echo "$l"; done < /proc/self/mountinfo); '
              'case "$m" in *rehearsal_*) echo quiet ;; *) cat /etc/hostname ;; esac')
    gate, _ = ga.setup(tmp_path / "w", quarantine=tmp_path / "q")
    detail, error = gate.run("c0", "shell", {"cmd": f"printf '%s\\n' '{script}' > s.sh; sh s.sh"})
    assert error and "withheld" in detail
    records, _ = _stream(gate.monitor, tmp_path / "q")
    assert [(r["trigger"]["layer"], r["trigger"]["reason"]) for r in records] == [("guard", gate.log[-1][2].upper())]


@pytest.mark.parametrize("args", [
    {"layer": "cw_vfs", "reason": "EXDEV", "call": "{}", "context": ""},     # the monitor's own
    {"layer": "ipc", "reason": "x", "call": "{}", "context": ""},
    {"layer": "vow", "reason": "", "call": "{}", "context": ""},
    {"layer": "vow", "reason": "x" * (monitor.Q_REASON + 1), "call": "{}", "context": ""},
    {"layer": "vow", "reason": "x", "call": "{}", "context": "not a hash"},
    {"layer": "vow", "reason": "x", "call": "{}", "context": "A" * 64},
], ids=["cw_vfs", "ipc", "no-reason", "long-reason", "bad-context", "upper-hex"])
def test_the_gate_reports_only_its_own_refusals(remote, args):
    """It decides Vow and guard refusals; cw_vfs, IPC and jail ones are the
    monitor's own. Anything else is not a refusal it may report."""
    with pytest.raises(monitor.MonitorGone):
        remote.call("quarantine", **args)
    assert remote._proc.wait(timeout=10) == monitor.PROTOCOL_EXIT


def _local(tmp_path, folder=True):
    return monitor.Monitor(default_signer("Monitor"), tmp_path / "work",
                           quarantine=(tmp_path / "q") if folder else None)

def test_a_tampered_stream_does_not_verify(tmp_path):
    m = _local(tmp_path)
    for i in range(3): m.report_refusal("vow", f"r{i}", monitor.canon({"op": "shell", "args": {"cmd": str(i)}}))
    records, cp = monitor.load_quarantine(os.path.join(tmp_path / "q", m.session))
    monitor.check_quarantine(records, cp, m.verifier, m.session)
    edited = [dict(r) for r in records]; edited[1]["trigger"] = dict(edited[1]["trigger"], reason="fine")
    for bad in (edited, records[:-1], [records[0], records[2], records[1]], records[1:]):
        with pytest.raises(monitor.SessionError):
            monitor.check_quarantine(bad, cp, m.verifier, m.session)
    with pytest.raises(monitor.SessionError):                                  # another session's
        monitor.check_quarantine(records, cp, m.verifier, "0" * 32)
    with pytest.raises(monitor.SessionError):                                  # a checkpoint re-signed by no one
        monitor.check_quarantine(records, dict(cp, signature="00"), m.verifier, m.session)


def test_a_full_stream_counts_what_it_no_longer_keeps(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "Q_MAX", 2)
    m = _local(tmp_path, folder=False)
    results = [m.report_refusal("guard", "LEARNING", "{}") for _ in range(4)]
    assert [rec is None for rec, _ in results] == [False, False, True, True]
    cp = results[-1][1]
    assert (cp["q_index"], cp["dropped"]) == (1, 2)
    monitor.check_quarantine(m.quarantine_records, cp, m.verifier, m.session)


def test_a_long_call_is_kept_clipped_and_hashed_whole(tmp_path):
    m = _local(tmp_path, folder=False)
    call = monitor.canon({"op": "file_write", "args": {"path": "big", "content": "é" * 10000}})
    rec, _ = m.report_refusal("vow", "forbidden:x", call)
    kept = rec["trigger"]["call_json"]
    assert len(kept.encode()) <= monitor.Q_FIELD and call.startswith(kept)
    assert rec["trigger"]["call_sha256"] == hashlib.sha256(call.encode()).hexdigest()


@pytest.mark.parametrize("where", ["inside the workdir", "holding the workdir"])
def test_a_quarantine_directory_overlapping_the_workdir_is_refused(tmp_path, where):
    """The workdir is what calls reach: a stream there could be rewritten by them."""
    work = tmp_path / "w"
    q = work / "q" if where == "inside the workdir" else tmp_path
    with pytest.raises(monitor.MonitorGone, match="overlaps the workdir"):
        monitor.RemoteMonitor(work, quarantine=q)
    with pytest.raises(monitor.QuarantineError):
        monitor.Monitor(default_signer("Monitor"), work, quarantine=q)


def test_the_command_line_keeps_the_stream_next_to_the_ledger(tmp_path):
    """--ledger L puts it under L.quarantine/<session>/, where the gate,
    once confined, cannot write: the monitor writes it and signs it."""
    from tests.test_backends import call as ocall, reply
    from tests.test_runs import _cli, _serve
    from ledger import Ledger
    srv = _serve((200, reply(tool_calls=[ocall(1, "file_read", {"path": "../outside"})], finish="tool_calls")),
                 (200, reply("done")))
    lp = tmp_path / "l.json"
    try: r = _cli(tmp_path, srv, "--ledger", str(lp))
    finally: srv.shutdown(); srv.server_close()
    assert r.returncode == 0, r.stderr
    [session] = os.listdir(tmp_path / "l.json.quarantine")
    records, checkpoint = monitor.load_quarantine(tmp_path / "l.json.quarantine" / session)
    monitor.check_quarantine(records, checkpoint, Ledger.load(str(lp)).verifiers["Monitor"], session)
    assert [(q["trigger"]["layer"], q["trigger"]["reason"]) for q in records] == [("cw_vfs", "EXDEV")]
    assert "quarantine: 1 refused call(s)" in r.stdout
    # verify.py checks it against the ledger's own (pinned) monitor key, and finds an edit
    import verify
    L = Ledger.load(str(lp)); pins = {s: v.key_id() for s, v in L.verifiers.items()}
    stream = tmp_path / "l.json.quarantine"
    ok, reasons, _ = verify.check(lp, pins, runs_path=str(lp) + ".runs.jsonl", quarantine=stream)
    assert ok, reasons
    path = stream / session / "records.jsonl"
    path.write_text(path.read_text().replace('"EXDEV"', '"ENOENT"'))
    ok, reasons, _ = verify.check(lp, pins, quarantine=stream)
    assert not ok and any(r.startswith(f"quarantine: {session}:") for r in reasons), reasons


@pytest.mark.skipif(not (os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK)), reason="no /dev/shm here")
def test_a_stream_the_gate_could_write_is_refused_before_anything_runs(tmp_path):
    """The confined gate may write /dev's files: a stream under /dev/shm would
    be its to rewrite."""
    from tests.test_backends import reply
    from tests.test_runs import _cli, _serve
    import shutil
    q = f"/dev/shm/dharma_quarantine_test_{os.getpid()}"
    srv = _serve((200, reply("done")))
    try: r = _cli(tmp_path, srv, "--quarantine", q)
    finally:
        srv.shutdown(); srv.server_close(); shutil.rmtree(q, ignore_errors=True)
    assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    assert "not starting:" in r.stderr and "which the gate may write" in r.stderr, r.stderr
    assert srv.seen == []
