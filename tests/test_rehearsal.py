"""Rehearsal: the critic judges what a plan really does, before it runs for real.

Without it, the jail catches what the critic missed only after the command
has run (contained, but run). With it, the plan first runs in the jail
against a throwaway copy of its workdir, and the critic judges that too."""
import os, tempfile

import pytest

import tests.support  # noqa: F401
import critic_loop
from critic_loop import CriticLoop, execute
from guard import Guard
from ledger import Ledger
from tests.test_jail import needs_jail
from vow import parse_vow

VOW = parse_vow("vow T\n  forbid read_sensitive_path forall action\n")

class Agent:
    """Does one fixed thing, whatever it is asked."""
    def __init__(self, *calls): self.calls = calls; self.sandbox = None
    def act(self, goal, context=""):
        for tool, kwargs in self.calls: getattr(self.sandbox, tool)(**kwargs)
        return self.sandbox.calls

# Writes a script and runs it: the dry run sees `sh s.sh`, and the script reads /etc/shadow.
HIDDEN = Agent(("file_write", {"path": "s.sh", "content": "cat /etc/shadow; echo ran > marker\n"}),
               ("shell", {"cmd": "sh s.sh"}))

def loop(agent, rehearse, guard=None):
    return CriticLoop(agent, VOW, verbose=False, max_retries=1, guard=guard, rehearse=rehearse)

@needs_jail
def test_without_rehearsal_the_critic_accepts_what_it_cannot_see():
    effects, ok, plan = loop(HIDDEN, rehearse=False).propose_and_verify("go")
    assert ok and "read_sensitive_path" not in effects

@needs_jail
def test_rehearsal_refuses_it_before_it_runs_for_real(tmp_path):
    L = Ledger("t"); g = Guard("G", L)
    effects, ok, plan = loop(HIDDEN, rehearse=True, guard=g).propose_and_verify("go", workdir=str(tmp_path))
    assert (ok, plan) == (False, [])
    assert [a.class_id for a in L.audits] == ["critic:read_sensitive_path"]
    assert not (tmp_path / "marker").exists() and not (tmp_path / "s.sh").exists()

@needs_jail
def test_a_script_already_in_the_workdir_is_rehearsed_too(tmp_path):
    """No dry run can see a file the plan did not write. The rehearsal runs
    against a copy of the workdir, so it does."""
    (tmp_path / "setup.sh").write_text("cat /etc/shadow\n")
    agent = Agent(("shell", {"cmd": "sh setup.sh"}))
    assert loop(agent, rehearse=False).propose_and_verify("go", workdir=str(tmp_path))[1] is True
    assert loop(agent, rehearse=True).propose_and_verify("go", workdir=str(tmp_path))[1] is False

@needs_jail
def test_the_rehearsal_leaves_the_real_workdir_alone(tmp_path):
    (tmp_path / "data.txt").write_text("original\n")
    agent = Agent(("shell", {"cmd": "echo changed > data.txt; rm -f data.txt; echo new > other.txt"}))
    effects, ok, plan = loop(agent, rehearse=True).propose_and_verify("go", workdir=str(tmp_path))
    assert ok
    assert (tmp_path / "data.txt").read_text() == "original\n" and not (tmp_path / "other.txt").exists()

@needs_jail
def test_a_rehearsed_plan_runs_as_predicted(tmp_path):
    agent = Agent(("file_write", {"path": "note.txt", "content": "hi\n"}), ("shell", {"cmd": "cat note.txt | wc -l"}))
    effects, ok, plan = loop(agent, rehearse=True).propose_and_verify("go", workdir=str(tmp_path))
    assert ok
    real, _ = execute(plan, effects, str(tmp_path), jail=True)
    assert "diverged" not in real and (tmp_path / "note.txt").exists()

def test_asked_to_rehearse_without_a_jail_accepts_nothing(tmp_path, monkeypatch):
    import jail
    monkeypatch.setattr(jail, "run", lambda *a, **k: (_ for _ in ()).throw(jail.JailUnavailable("no jail here")))
    L = Ledger("t"); g = Guard("G", L)
    c = loop(Agent(("shell", {"cmd": "ls"})), rehearse=True, guard=g)
    effects, ok, plan = c.propose_and_verify("go", workdir=str(tmp_path))
    assert (ok, plan) == (False, []) and c.unchecked == 1 and L.audits == []

@needs_jail
def test_what_the_critic_saw_in_rehearsal_is_not_divergence(tmp_path):
    """The rehearsal is the prediction. A script that reads outside the
    workdir is seen there, so a Vow forbidding `diverged` still accepts it."""
    (tmp_path / "setup.sh").write_text("cat /etc/hostname\n")
    vow = parse_vow("vow T\n  forbid diverged forall action\n")
    c = CriticLoop(Agent(("shell", {"cmd": "sh setup.sh"})), vow, verbose=False, max_retries=1, rehearse=True)
    effects, ok, plan = c.propose_and_verify("go", workdir=str(tmp_path))
    assert ok and "read_outside_workdir" in effects and "diverged" not in effects
    real, _ = execute(plan, effects, str(tmp_path), jail=True)
    assert "diverged" not in real
