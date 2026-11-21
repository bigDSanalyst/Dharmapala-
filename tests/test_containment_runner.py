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
                                           "jail.py", '["bwrap", ', '["false", '))
    assert baseline["passed"] and not ok
    assert r["status"] == "SURVIVED" and not r["caught_by"] and r["other_failures"]

def test_a_real_break_is_a_catch(monkeypatch):
    ok, _, [r] = only(monkeypatch, ("environment kept", "", "jail.py", '"--clearenv", ', ''))
    assert ok and r["status"] == "caught" and r["caught_by"] == ["test_the_host_environment_is_not_inherited"]

def test_a_mutant_that_no_longer_applies_is_not_passed_over(monkeypatch):
    ok, _, [r] = only(monkeypatch, ("gone", "", "jail.py", '"--no-such-flag",', ''))
    assert not ok and r["status"] == "stale"

def test_a_bubblewrap_break_is_tested_without_confine(monkeypatch):
    """With confine.py on, Landlock stops the write a writable host root would
    let through, and the break would survive. Bubblewrap's flags are therefore
    broken with confine.py off, and the read-only root's own probe catches it
    (among others: a writable host root is a visible one too)."""
    ok, baseline, [r] = only(monkeypatch, ("host root writable", "", "jail.py",
                                           '["bwrap", *_system_binds(),', '["bwrap", "--bind", "/", "/",'))
    assert ok and "test_the_host_filesystem_is_read_only" in r["caught_by"]
    assert set(baseline["alone"]["jail.py"]["escapes"]) == cm.LAYERS["jail.py"]["other_only"]

def test_a_confine_break_is_tested_with_the_whole_host_bound(monkeypatch):
    """With the narrow binds on, the host's sockets are not in the jail at all,
    and a filter that let Unix sockets through would survive. confine.py is
    therefore broken with the whole host mounted read-only."""
    ok, baseline, [r] = only(monkeypatch, ("unix sockets allowed", "", "confine.py",
                                           "AF_UNIX = 1\n", "AF_UNIX = 99\n"))
    assert ok and set(r["caught_by"]) == {"test_unix_sockets_cannot_be_made",
                                          "test_host_unix_sockets_are_unreachable"}
    assert set(baseline["alone"]["confine.py"]["escapes"]) == cm.LAYERS["confine.py"]["other_only"]

def test_a_confine_break_is_a_catch(monkeypatch):
    ok, _, [r] = only(monkeypatch, ("seccomp off", "", "confine.py", "    _seccomp(libc)\n", ""))
    assert ok and r["status"] == "caught" and \
        set(r["caught_by"]) == {"test_calls_the_trace_cannot_see_are_refused",
                                "test_unix_sockets_cannot_be_made", "test_host_unix_sockets_are_unreachable"}
