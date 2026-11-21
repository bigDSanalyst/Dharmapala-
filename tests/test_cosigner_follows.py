"""The co-signer follows the session (Phase 3, slice 2; docs/monitor-boundary.md, §5).

Each run it is shown must start at the checkpoint the last one ended on. One
that does not means a run was hidden from it, which an honest gate never
does: it refuses that run and signs nothing more in the session, and in its
own process (cosigner.py) it ends. A run the guard refuses before asking it
to vouch is still shown to it, and a run it refuses for what it found in it
still counts as shown. It signs no decision that cites no run of the session.
`verify.py` finds a run hidden past the gate too, offline, as before."""
import pytest

import tests.support  # noqa: F401
import cosigner
import guarded_agent as ga
import runs
from tests.test_jail import needs_jail
from to_coq_witness import ConfigError, RefusedToSign, propose, build_certificate

TRAJECTORY_VOW = ga.DEFAULT_VOW + "  trajectory no_write_after_read: never verb:file_write after verb:file_read\n"
WHERE = ["its own process", "the gate's process"]

def _setup(tmp_path, where, without, **kw):
    if where == "the gate's process": without("dilithium-py")
    gate, L = ga.setup(tmp_path / "work", **kw)
    assert isinstance(gate.co_signer, cosigner.RemoteCoSigner) == (where == "its own process")
    return gate, L

def _hidden(gate, monkeypatch, call_id, tool, args):
    """Run a call through the gate, with its co-signer never shown the run.
    Returns what the gate would have shown it."""
    kept = {}
    def hide(proposal, cert_path, inputs, binary_path, re_run_fn, decision=None, evidence=None, snapshot=None):
        kept.update(proposal=proposal, inputs=inputs, decision=decision, evidence=evidence)
        raise ConfigError("not shown")
    with monkeypatch.context() as m:
        m.setattr(gate.co_signer, "cosign", hide)
        gate.run(call_id, tool, args)
    return kept


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("how", ["through the gate", "past the gate"])
def test_a_run_hidden_from_the_co_signer_ends_its_signing(tmp_path, monkeypatch, without, where, how):
    gate, L = _setup(tmp_path, where, without)
    assert not gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})[1]
    if how == "through the gate":
        _hidden(gate, monkeypatch, "c1", "file_write", {"path": "hidden.txt", "content": "h"})
    else:                                               # a real call the guard never judged
        gate.monitor.sandbox(gate.workdir).file_write("hidden.txt", "h")
        gate.monitor.end_run()
    before = len(L.attestations)
    detail, error = gate.run("c2", "file_write", {"path": "b.txt", "content": "y"})
    assert error and "was hidden from the co-signer" in detail and "withheld" in detail, detail
    detail, error = gate.run("c3", "file_read", {"path": "a.txt"})
    assert error and "was hidden from the co-signer" in detail and "nothing more runs in this session" in detail, detail
    assert len(L.attestations) == before
    if where == "its own process":
        assert gate.co_signer._proc._proc.wait(timeout=30) == cosigner.PROTOCOL_EXIT
    problems = runs.verify(gate.runs.entries, L)
    if how == "past the gate":                          # the gate's records have no entry for it
        assert any("a run the monitor recorded is missing" in p for p in problems), problems
    else:                                               # offline, it is one more withheld run
        assert problems == []


def test_once_it_stops_it_signs_not_even_the_run_that_was_hidden(tmp_path, monkeypatch, without):
    """Shown after the run that gave it away, the hidden run starts where the
    co-signer's last run ended. It is refused all the same."""
    gate, _ = _setup(tmp_path, "the gate's process", without)
    assert not gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})[1]
    kept = _hidden(gate, monkeypatch, "c1", "file_write", {"path": "hidden.txt", "content": "h"})
    assert gate.run("c2", "file_write", {"path": "b.txt", "content": "y"})[1]
    with pytest.raises(RefusedToSign, match="was hidden from the co-signer"):
        gate.co_signer.cosign(kept["proposal"], "", kept["inputs"], gate.binary_path, ga._engine,
                              decision=kept["decision"], evidence=kept["evidence"])
    assert "was hidden from the co-signer" in gate.co_signer.observe(kept["evidence"])


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("refused_by", ["the trajectory clauses", "the trajectory co-signer"])
def test_a_run_the_guard_refused_before_asking_it_to_vouch_is_still_shown(tmp_path, monkeypatch, without, where,
                                                                          refused_by):
    gate, L = _setup(tmp_path, where, without, vow_source=TRAJECTORY_VOW)
    if refused_by == "the trajectory clauses":
        for i, (tool, args) in enumerate([("file_write", {"path": "a.txt", "content": "x"}),
                                          ("file_read", {"path": "a.txt"}),
                                          ("file_write", {"path": "b.txt", "content": "y"})]):   # after a read
            gate.run(f"c{i}", tool, args)
        assert [entry[2] for entry in gate.log] == ["lawful", "lawful", "learning"]
    else:
        with monkeypatch.context() as m:
            m.setattr(gate.traj_cosigner, "cosign", lambda *a: (False, "not this one"))
            detail, error = gate.run("c0", "file_write", {"path": "a.txt", "content": "x"})
        assert error and "not this one" in detail, detail
    detail, error = gate.run("c9", "file_read", {"path": "a.txt"})
    assert not error, detail
    assert "session: follows the last run shown" in gate.co_signer.notes and L.verify_integrity()


@needs_jail
@pytest.mark.parametrize("where", WHERE)
def test_a_run_refused_for_what_was_found_in_it_still_counts_as_shown(tmp_path, monkeypatch, without, where):
    gate, _ = _setup(tmp_path, where, without)
    with monkeypatch.context() as m:
        m.setattr(gate.co_signer, "snapshot", lambda workdir: None)        # nothing to replay it from
        detail, error = gate.run("c0", "shell", {"cmd": "echo hi > a.txt"})
    assert error and "re-execution: NO SNAPSHOT" in gate.co_signer.notes, detail
    assert "session: follows the last run shown" in gate.co_signer.notes
    detail, error = gate.run("c1", "file_read", {"path": "a.txt"})
    assert not error, detail


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("decided", [True, False])
def test_it_signs_no_decision_that_cites_no_run_of_the_session(tmp_path, without, where, decided):
    """It would be signed outside the session's chain, where the co-signer
    cannot follow it."""
    from decision import Decision
    from vow import Action
    gate, L = _setup(tmp_path, where, without)
    a = Action(id="c0", verb="file_write", domain="action"); a._observed_effects = set()
    d = Decision.of(a, gate.vow)                                   # no run record behind it
    inputs, outputs = {"tool_use_id": "c0"}, ga._engine({})
    cert = build_certificate("Guard_0", outputs, d if decided else None)
    proposal = propose("Guard", "guard", gate.binary_hash, 0, inputs, cert, outputs, gate.co_signer.id,
                       decision=d if decided else None)
    with pytest.raises(RefusedToSign, match="cites no run"):
        gate.co_signer.cosign(proposal, "", inputs, gate.binary_path, ga._engine, decision=d if decided else None)
    assert gate.co_signer.notes[-1] == "session: NO RUN"
