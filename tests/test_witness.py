"""The co-signer reads the raw trace with its own parser.

If the co-signer re-derived effects from the events the guard's side parsed,
a fault in jail.parse would be signed twice. witness.py is a second parser of
the same raw trace, built differently and sharing no code with jail.parse. The
two agree on honest runs; when the guard's parser is broken, the co-signer's
reading still shows what ran, and it refuses."""
import ast, hashlib, os, pathlib, tempfile

import pytest

import tests.support  # noqa: F401
import jail, witness
from critic_loop import effects_from_evidence, evidence_of, execute
from guard import Guard, VerdictKind
from ledger import Ledger
from signing import default_signer, verifier_for
from tests.test_jail import needs_jail
from to_coq_witness import CoSigner
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

VOW = parse_vow("vow T\n  forbid read_sensitive_path forall action\n  forbid diverged forall action\n")
INPUTS = {"butterflies": [(1, 2, 3)]}
ROOT = pathlib.Path(__file__).resolve().parent.parent

def engine(inputs):
    a, b, w = inputs["butterflies"][0]
    return {"butterflies": [{"a": a, "b": b, "w": w, "ea": (a + w * b) % 3329,
                             "eb": (a + (3329 - w) * b) % 3329}]}

@pytest.fixture
def binary():
    fd, path = tempfile.mkstemp(); os.write(fd, b"engine"); os.close(fd)
    yield path, hashlib.sha256(b"engine").hexdigest()
    os.remove(path)

def rig():
    L = Ledger("t"); g = Guard("G", L)
    s_co, s_tr = default_signer("Co"), default_signer("Tr")
    for s in (s_co, s_tr): L.register_verifier(verifier_for(s))
    return L, g, CoSigner(s_co), TrajectoryCoSigner(s_tr)

def engage(evidence, reported, binary):
    L, g, co, tr = rig()
    a = Action(id="a", verb="execute", domain="action")
    a._observed_effects = set(reported); a._evidence = evidence
    return g.engage(a, VOW, co, tr, "c0", INPUTS, engine, *binary), co

# --- independence ------------------------------------------------------------------------

def test_the_co_signers_parser_shares_no_code_with_the_guards():
    tree = ast.parse((ROOT / "witness.py").read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"os"}, imported          # not jail, not observation, not even re

# --- the tokenizer, on lines that trip naive parsing -------------------------------------

def one(line, cmd="x"):
    root = 'execve("/bin/sh", ["sh", "-c", "x"], 0x1 /* 2 vars */) = 0\n'
    return witness.parse({1: root + line}, cmd)

def test_commas_parens_and_quotes_inside_a_path_stay_in_the_path():
    ev = one('openat(AT_FDCWD</w>, "/etc/a, b) = \\"c\\"", O_RDONLY) = -1 ENOENT (No such file)')
    assert ev == [("read", '/etc/a, b) = "c"', False)]

def test_the_resolved_path_of_a_successful_open_wins():
    ev = one('openat(AT_FDCWD</w>, "e/hostname", O_RDONLY) = 3</etc/hostname>')
    assert ev == [("read", "/etc/hostname", True)]

def test_a_failed_relative_open_is_joined_to_its_directory():
    ev = one('openat(5</w/sub>, "f", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)')
    assert ev == [("write", "/w/sub/f", False)]

def test_a_failed_open_through_a_symlink_is_judged_where_it_leads(tmp_path):
    """A failed open reports no file. The symlink the command left behind is
    still there, so the name is resolved through it: e/missing is /etc/missing."""
    (tmp_path / "e").symlink_to("/etc")
    ev = one(f'openat(AT_FDCWD<{tmp_path}>, "e/missing", O_RDONLY) = -1 ENOENT (No such file)')
    assert ev == [("read", "/etc/missing", False)]

def test_octal_escapes_and_truncation():
    ev = one('execve("/bin/echo", ["echo", "a\\tb\\303\\251", "long"...], 0x1 /* 2 vars */) = 0')
    assert ev == [("exec", ("echo", "a\tb\xc3\xa9", "long"), True)]

def test_before_the_command_starts_nothing_counts():
    trace = {1: 'openat(AT_FDCWD</>, "/etc/shadow", O_RDONLY) = 3</etc/shadow>\n'
                'execve("/bin/sh", ["sh", "-c", "x"], 0x1 /* 2 vars */) = 0\n'}
    assert witness.parse(trace, "x") == []

def test_children_are_followed_through_the_pid_namespace():
    trace = {1: 'execve("/bin/sh", ["sh", "-c", "x"], 0x1 /* 2 vars */) = 0\n'
                'vfork()                                 = 3 /* 7 in strace\'s PID NS */\n',
             7: 'execve("/bin/cat", ["cat", "/etc/shadow"], 0x1 /* 2 vars */) = 0\n'
                'openat(AT_FDCWD</w>, "/etc/shadow", O_RDONLY) = 3</etc/shadow>\n',
             9: 'openat(AT_FDCWD</w>, "/root/x", O_RDONLY) = 3</root/x>\n'}   # not a descendant
    assert witness.parse(trace, "x") == [("exec", ("cat", "/etc/shadow"), True),
                                         ("read", "/etc/shadow", True)]

def test_a_trace_that_never_runs_the_command_is_no_reading():
    assert witness.parse({1: 'execve("/bin/sh", ["sh", "-c", "y"], 0x1) = 0\n'}, "x") is None

# --- agreement on honest runs -------------------------------------------------------------

COMMANDS = [
    "ls -la",
    "cat /etc/hostname; echo hi > out.txt; mv out.txt o2; rm o2",
    "ln -s /etc e; cat e/hostname; cd /etc && cat hostname",
    "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh 2>/dev/null",
    "(echo x | wc) ; kill -9 -1; true",
    "python3 -c 'import socket; s = socket.socket(); s.settimeout(0.2)\ntry: s.connect((\"10.9.8.7\", 80))\nexcept OSError: pass'",
    "echo \"a, b) = c\" > 'odd, name'; cat 'odd, name' $(echo /etc/passwd)",
]

@needs_jail
@pytest.mark.parametrize("cmd", COMMANDS)
def test_both_parsers_read_an_honest_run_the_same_way(cmd, tmp_path):
    ex = jail.run(cmd, str(tmp_path))
    assert ex.events, "nothing observed"
    assert witness.parse(ex.trace, cmd) == ex.events

# --- the guard's parser broken; the co-signer's is not ------------------------------------

def _drops(path):
    real = jail.parse
    def broken(per_pid, cmd):
        events = real(per_pid, cmd)
        return None if events is None else [e for e in events if path not in str(e[1])]
    return broken

@needs_jail
@pytest.mark.parametrize("breakage", ["drop the open", "see nothing"])
def test_a_broken_guard_parser_is_caught_by_the_co_signers_own(breakage, tmp_path, monkeypatch, binary):
    """The script opens /etc/shadow. The guard's parser is broken so it never
    reports that; the guard's own verdict would be LAWFUL. The co-signer reads
    the raw trace itself, sees the open, and refuses."""
    monkeypatch.setattr(jail, "parse", _drops("/etc/shadow") if breakage == "drop the open"
                        else (lambda per_pid, cmd: []))
    cmd = "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh"
    dry = {"exec", "exec_unvetted", "write", "read"}
    work = str(tmp_path / "run")
    guard_view, calls = execute([("shell", {"cmd": cmd})], dry, work, jail=True)
    assert "read_sensitive_path" not in guard_view           # the guard's side is blind to it
    ev = evidence_of(calls, work, dry)
    assert effects_from_evidence(ev) == guard_view           # and its events agree with it
    v, co = engage(ev, guard_view, binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL
    assert "read_sensitive_path" in v.reason and "effects: MISMATCH" in co.notes

@needs_jail
def test_an_honest_jailed_run_is_signed(tmp_path, binary):
    cmd = "ls -la; cat /etc/hostname"
    dry = {"exec", "read", "read_outside_workdir"}
    work = str(tmp_path / "run")
    effects, calls = execute([("shell", {"cmd": cmd})], dry, work, jail=True)
    v, co = engage(evidence_of(calls, work, dry), effects, binary)
    assert v.kind == VerdictKind.LAWFUL, v.reason
    assert "effects: re-derived, match" in co.notes

# --- a record the co-signer cannot read ---------------------------------------------------

def jailed(result):
    return evidence_of([("shell", {"cmd": "x"}, dict({"ok": True, "jailed": True, "events": []}, **result))],
                       "/work", {"exec"})

@pytest.mark.parametrize("result, why", [
    ({}, "carries no raw trace"),
    ({"trace": {}}, "carries no raw trace"),
    ({"trace": {"1": 'execve("/bin/sh", ["sh", "-c", "other"], 0x1) = 0\n'}}, "never shows the command"),
])
def test_a_jailed_call_without_a_readable_trace_is_refused(result, why, binary):
    v, co = engage(jailed(result), {"exec"}, binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL and why in v.reason
    assert "trace: UNREADABLE" in co.notes
