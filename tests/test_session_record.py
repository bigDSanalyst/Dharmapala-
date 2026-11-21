"""The monitor's session record: every real call in a signed chain, every
witness bound to the session's workdir (F3; docs/monitor-boundary.md, 5).

A witness proves a file call was confined beneath some root, and nothing
checked which: a well-formed witness from any directory verified. Now the
monitor signs a session header naming the workdir and its root (dev, ino),
chains every real call, and signs a checkpoint at the end of each run. The
co-signer checks each run against it before vouching, and verify.py checks
the run records against it afterwards.

The forgeries below re-chain the run-record file the way a forger who can
edit it would (tests/test_runs.py's rechain), so the run records' own chain
passes and only the session record can show them."""
import json

import pytest

import tests.support  # noqa: F401
import cw_vfs
import monitor
import runs
from signing import default_signer, verifier_for
from tests.test_runs import colab_cell_b, fresh, rechain
from tools import Sandbox


def test_every_run_is_in_one_signed_chain(tmp_path):
    entries, L = fresh(tmp_path)
    assert [e["session"]["checkpoint"]["index"] for e in entries] == [0, 1, 2]
    assert [e["session"]["from_checkpoint"] for e in entries][0] is None
    assert len({e["session"]["header"]["session"] for e in entries}) == 1
    assert runs.verify(entries, L) == []


def test_the_co_signer_checks_each_run_against_the_session(tmp_path):
    gate, L, _ = colab_cell_b(tmp_path)
    assert "session: signed, chained, witnesses bound to its root" in gate.co_signer.notes
    gate.monitor = None                      # the gate stops recording; the co-signer still checks
    _, error = gate.run("c9", "file_write", {"path": "x.txt", "content": "y"})
    assert error and "session: REFUSED" in gate.co_signer.notes


# --- forgeries of the run records, each re-chained to hide it --------------------------------

def _both(e, f):
    """Apply f to the session block, in the entry and in its stored record."""
    f(e["session"])
    if e.get("evidence") is not None: e["evidence"]["session"] = e["session"]

def _drop_a_run(es): del es[1]; rechain(es)
def _edit_a_record(es):
    _both(es[1], lambda b: b["records"][0].update(args_sha256="0" * 64)); rechain(es)
def _rewrite_a_call(es):
    es[1]["evidence"]["calls"][0][1]["content"] = "alpha\nbeta\ngamma"; rechain(es)
def _resign(es):
    forger = default_signer("Monitor")
    for e in es:
        def resign(b):
            b["header"]["monitor_key_id"] = verifier_for(forger).key_id()
            b["header_signature"] = forger.sign(monitor.canon(b["header"]).encode()).hex()
        _both(e, resign)
    rechain(es)
def _swap_blocks(es):
    es[1]["session"], es[2]["session"] = es[2]["session"], es[1]["session"]; rechain(es)

@pytest.mark.parametrize("forge, why", [
    (_drop_a_run, "run 1: does not follow the session's run before it"),
    (_edit_a_record, "run 1: the run's checkpoint does not sign the head of its records"),
    (_rewrite_a_call, "run 1: call 0 is not the call the monitor recorded"),
    (_resign, "run 0: the session header is not signed by the monitor's key"),
    (_swap_blocks, "run 1: its session block is not its run record's"),
])
def test_a_forged_run_record_fails_the_session_check(tmp_path, forge, why):
    entries, L = fresh(tmp_path)
    forge(entries)
    problems = runs.verify(entries, L)
    assert any(why in p for p in problems), problems


def test_verify_py_fails_a_dropped_run_the_ledger_cannot_see(tmp_path):
    """A run whose output was withheld leaves no stored record and no ledger
    signature over its content, but its session block stays: drop the entry,
    re-chain the file, and the monitor's chain still shows the hole."""
    colab_cell_b(tmp_path, ledger=True)
    from ledger import Ledger
    import verify
    L = Ledger.load(str(tmp_path / "ledger.json"))
    pins = {sid: v.key_id() for sid, v in L.verifiers.items()}
    assert "Monitor" in pins
    rp = tmp_path / "ledger.json.runs.jsonl"
    es = runs.load(str(rp)); del es[1]; rechain(es)
    rp.write_text("".join(runs._canon(e) + "\n" for e in es))
    ok, reasons, _ = verify.check(tmp_path / "ledger.json", pins, runs_path=rp)
    assert not ok and any("does not follow the session's run before it" in r for r in reasons), reasons


# --- F3: a witness is checked against the session's root -------------------------------------

@pytest.fixture
def session(tmp_path):
    signer = default_signer("Monitor")
    work = tmp_path / "work"
    return monitor.Monitor(signer, work), verifier_for(signer), work


def _run(sb, mon, *calls):
    mon.begin_run()
    try:
        for tool, kw in calls: getattr(sb, tool)(**kw)
    finally:
        sb.close()
    return {"workdir": str(sb.logical_workdir), "calls": [list(c) for c in sb.calls],
            "session": mon.end_run()}


def test_a_witness_from_another_root_is_refused(tmp_path, session):
    mon, v, work = session
    other = tmp_path / "other"; other.mkdir(); (other / "notes.txt").write_text("from elsewhere\n")
    ev = _run(Sandbox(other, monitor=mon), mon, ("file_read", {"path": "notes.txt"}))
    tool, kwargs, result = ev["calls"][0]
    wit = cw_vfs.CapabilityWitness.from_dict(result["capability_witness"])
    assert cw_vfs.verify_witness_against_call(wit, tool, kwargs, result)[0]   # F3: the witness alone passes
    monitor.check_block(ev["session"], v, work, [tuple(c) for c in ev["calls"]])   # and the chain is sound
    with pytest.raises(monitor.SessionError, match="from another root than the session's"):
        monitor.check_evidence(ev, v, work)


def test_a_witness_naming_a_file_outside_the_workdir_is_refused(session):
    mon, v, work = session
    (work / "a.txt").write_text("x")
    ev = _run(Sandbox(work, monitor=mon), mon, ("file_read", {"path": "a.txt"}))
    monitor.check_evidence(ev, v, work)
    calls = [tuple(c) for c in ev["calls"]]
    calls[0][2]["capability_witness"]["fd_realpath"] = "/etc/passwd"
    with pytest.raises(monitor.SessionError, match="outside the session's workdir"):
        monitor.check_witnesses(mon.header, calls)


@pytest.mark.parametrize("mangle, why", [
    (lambda b, w: b.pop("header"), "no session header"),
    (lambda b, w: b["header"].update(workdir="/elsewhere"), "not signed by the monitor's key"),
    (lambda b, w: b["checkpoint"].update(index=7), "does not sign the head"),
    (lambda b, w: b["checkpoint"].update(signature="00" * 64), "does not sign the head"),
    (lambda b, w: b["records"].pop(), "does not sign the head"),
    (lambda b, w: b["records"][0].update(session="0" * 32), "a record from another session"),
])
def test_a_mangled_session_block_is_refused(session, mangle, why):
    mon, v, work = session
    ev = _run(Sandbox(work, monitor=mon), mon, ("file_write", {"path": "a.txt", "content": "x"}))
    block = json.loads(json.dumps(ev["session"]))
    mangle(block, work)
    with pytest.raises(monitor.SessionError, match=why):
        monitor.check_block(block, v, work)


def test_the_header_binds_the_workdir_the_policy_and_the_key(tmp_path, session):
    mon, v, work = session
    ev = _run(Sandbox(work, monitor=mon), mon, ("file_write", {"path": "a.txt", "content": "x"}))
    with pytest.raises(monitor.SessionError, match="the session is for"):
        monitor.check_block(ev["session"], v, tmp_path / "other")
    with pytest.raises(monitor.SessionError, match="names another policy"):
        monitor.check_block(ev["session"], v, work, policy_hash="f" * 64)
    with pytest.raises(monitor.SessionError, match="not signed by the monitor's key"):
        monitor.check_block(ev["session"], verifier_for(default_signer("Monitor")), work)


def test_runs_chain_from_one_checkpoint_to_the_next(session):
    mon, v, work = session
    first = _run(Sandbox(work, monitor=mon), mon, ("file_write", {"path": "a.txt", "content": "x"}))
    second = _run(Sandbox(work, monitor=mon), mon, ("file_read", {"path": "a.txt"}),
                  ("http_get", {"url": "https://example.org/"}))
    assert second["session"]["from_checkpoint"] == first["session"]["checkpoint"]
    for ev in (first, second): monitor.check_evidence(ev, v, work)
    forged = json.loads(json.dumps(second["session"]))
    forged["from_checkpoint"]["head"] = "0" * 64
    with pytest.raises(monitor.SessionError, match="starting checkpoint is not the monitor's"):
        monitor.check_block(forged, v, work)
