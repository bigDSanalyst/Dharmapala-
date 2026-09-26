"""The containment mutation runner counts only real catches.

A mutant is caught when a probe saw an escape. A mutant that stops the jail
from starting at all makes probes fail too, but for the wrong reason: the
runner must report it as surviving, or it would call a broken guard a
working one."""
import pytest

import tests.support  # noqa: F401
import containment_mutants as cm
from tests.test_jail import needs_jail

pytestmark = needs_jail

def only(monkeypatch, *mutants):
    monkeypatch.setattr(cm, "MUTANTS", list(mutants))
    monkeypatch.setattr(cm, "UNTESTED", {})
    monkeypatch.setattr(cm, "equivalent", lambda: {})
    return cm.run()

def test_a_jail_that_does_not_start_is_not_a_catch(monkeypatch):
    ok, baseline, [r] = only(monkeypatch, ("no jail", "bubblewrap is replaced by a program that fails",
                                           '["bwrap", ', '["false", '))
    assert baseline["passed"] and not ok
    assert r["status"] == "SURVIVED" and not r["caught_by"] and r["other_failures"]

def test_a_real_break_is_a_catch(monkeypatch):
    ok, _, [r] = only(monkeypatch, ("environment kept", "", '"--clearenv", ', ''))
    assert ok and r["status"] == "caught" and r["caught_by"] == ["test_the_host_environment_is_not_inherited"]

def test_a_mutant_that_no_longer_applies_is_not_passed_over(monkeypatch):
    ok, _, [r] = only(monkeypatch, ("gone", "", '"--no-such-flag",', ''))
    assert not ok and r["status"] == "stale"
