"""Landlock on the gate (Phase 2, slice 3b; gate_confine.py).

The exit test of docs/monitor-boundary.md's Phase 2: the gate, the process
that parses everything untrusted, cannot open the workdir. Landlock is for
good once applied, so each test confines a process of its own: a script, or
guarded_agent's command line, which confines itself once its monitors run."""
import json
import os
import shutil
import subprocess
import sys

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
import gate_confine
from tests.test_jail import needs_jail
from tests.test_runs import _cli, _serve


def _confined(script, tmp_path, *argv):
    """Run `script` in a fresh process that may confine itself; its JSON output.
    Its temporary files, the gate's scratch directory among them, go in tmp_path."""
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(ROOT)!r})\n" + script,
                        *argv], capture_output=True, text=True, timeout=300, cwd=str(ROOT),
                       env=dict(os.environ, TMPDIR=str(tmp_path)))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


PROBE = r'''
import json, os
import guarded_agent as ga, gate_confine, runs
W = sys.argv[1]
gate, L = ga.setup(W)
scratch = gate_confine.confine_gate(W)
reach = {}
def attempt(name, fn):
    try: fn(); reach[name] = "opened"
    except PermissionError: reach[name] = "refused"
attempt("read", lambda: open(W + "/notes.txt").read())
attempt("list", lambda: os.listdir(W))
attempt("write", lambda: open(W + "/planted.txt", "w"))
attempt("through /proc/self/root", lambda: open("/proc/self/root" + W + "/notes.txt").read())
os.symlink(W, scratch + "/link")
attempt("through a symlink of its own", lambda: open(scratch + "/link/notes.txt").read())
calls = []
for i, (tool, args) in enumerate([("file_write", {"path": "from_gate.txt", "content": "through the monitor"}),
                                  ("file_read", {"path": "notes.txt"}),
                                  ("shell", {"cmd": "cat notes.txt > copy.txt"})]):
    detail, error = gate.run(f"c{i}", tool, args)
    calls.append([tool, error, detail, list(gate.co_signer.notes)])
print(json.dumps({"reach": reach, "calls": calls, "verify": runs.verify(gate.runs.entries, L),
                  "tmpdir": os.environ.get("TMPDIR"), "scratch": scratch}))
'''

@needs_jail
def test_the_gate_cannot_reach_the_workdir_and_every_call_still_runs(tmp_path):
    work = tmp_path / "work"; work.mkdir(); (work / "notes.txt").write_text("alpha\n")
    out = _confined(PROBE, tmp_path, str(work))
    assert set(out["reach"].values()) == {"refused"}, out["reach"]
    for tool, error, detail, notes in out["calls"]:
        assert not error, (tool, detail)
        if tool == "shell": assert "re-execution: match" in notes
    assert out["verify"] == [] and out["tmpdir"] == out["scratch"]
    assert (work / "from_gate.txt").read_text() == "through the monitor"
    assert (work / "copy.txt").read_text() == "alpha\n" and not (work / "planted.txt").exists()


HOLDS_A_DESCRIPTOR = r'''
import json, os, gate_confine
W = sys.argv[1]
fd = os.open(W, os.O_RDONLY | os.O_DIRECTORY)        # opened before: Landlock does not revoke it
try: gate_confine.confine_gate(W); print(json.dumps({"refused": None}))
except gate_confine.Refused as e: print(json.dumps({"refused": str(e)}))
'''

def test_a_descriptor_into_the_workdir_held_from_before_is_refused(tmp_path):
    work = tmp_path / "work"; work.mkdir()
    out = _confined(HOLDS_A_DESCRIPTOR, tmp_path, str(work))
    assert out["refused"] and "holds a descriptor into the workdir" in out["refused"]


@pytest.mark.parametrize("where", ["inside the repository", "holding the ledger"])
def test_a_workdir_the_gate_must_keep_reaching_is_refused_before_anything_runs(tmp_path, where):
    from tests.test_backends import reply
    srv = _serve((200, reply("done")))
    work = ROOT / f".gate_landlock_test_{os.getpid()}" if where == "inside the repository" else tmp_path / "w"
    work.mkdir(exist_ok=True)
    ledger = (work if where == "holding the ledger" else tmp_path) / "l.json"
    try:
        r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(work),
                            "--backend", "openai-compatible", "--model", "m", "--ledger", str(ledger),
                            "--base-url", f"http://127.0.0.1:{srv.server_port}/v1"],
                           capture_output=True, text=True, timeout=120, env=dict(os.environ, TMPDIR=str(tmp_path)))
    finally:
        srv.shutdown(); srv.server_close()
        if where == "inside the repository": shutil.rmtree(work, ignore_errors=True)
    assert r.returncode == 1 and "not starting: the workdir" in r.stderr and "overlaps" in r.stderr, r.stderr
    assert srv.seen == []                                          # the model was never asked
    assert not ledger.exists() and not os.path.exists(str(ledger) + ".runs.jsonl")


@needs_jail
def test_the_command_line_confines_the_gate(tmp_path):
    from tests.test_backends import call as ocall, reply
    srv = _serve((200, reply(tool_calls=[ocall(1, "file_write", {"path": "a.txt", "content": "alpha"})],
                             finish="tool_calls")),
                 (200, reply(tool_calls=[ocall(2, "shell", {"cmd": "cat a.txt > b.txt"})], finish="tool_calls")),
                 (200, reply("done")))
    lp = tmp_path / "l.json"
    try: r = _cli(tmp_path, srv, "--ledger", str(lp))
    finally: srv.shutdown(); srv.server_close()
    assert r.returncode == 0, r.stderr
    assert "gate: confined (Landlock)" in r.stderr
    assert (tmp_path / "w" / "b.txt").read_text() == "alpha"
    from ledger import Ledger
    import verify
    L = Ledger.load(str(lp))
    ok, reasons, _ = verify.check(lp, {s: v.key_id() for s, v in L.verifiers.items()},
                                  runs_path=str(lp) + ".runs.jsonl")
    assert ok, reasons


def test_what_the_gate_keeps_never_includes_the_workdir(tmp_path):
    work = tmp_path / "work"; work.mkdir()
    rules = gate_confine.plan(str(tmp_path / "scratch"), files=[str(tmp_path / "l.json")])
    assert gate_confine.conflicts(str(work), rules) == []
    assert gate_confine.conflicts(str(ROOT / "x"), rules) == [str(ROOT)]
    assert gate_confine.conflicts(str(tmp_path), rules) == sorted([str(tmp_path / "scratch"), str(tmp_path / "l.json")])
    assert all(rights & ~gate_confine.FILE_RIGHTS == 0 for p, rights in rules if p.endswith("l.json"))


KILLED = r'''
import os, signal, gate_confine
scratch = gate_confine.confine_gate(sys.argv[1])
open(os.path.join(scratch, "critic_x.lean"), "w").write("-- left behind")
print(scratch, flush=True)
os.kill(os.getpid(), signal.SIGKILL)
'''

def test_the_scratch_directory_goes_when_the_gate_does_however_it_ends(tmp_path):
    import time
    work = tmp_path / "work"; work.mkdir()
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(ROOT)!r})\n" + KILLED,
                        str(work)], capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, TMPDIR=str(tmp_path)))
    scratch = r.stdout.strip()
    assert r.returncode == -9 and scratch.startswith(str(tmp_path))
    for _ in range(100):                         # the reaper sees the pipe close, then removes it
        if not os.path.exists(scratch): break
        time.sleep(0.05)
    assert not os.path.exists(scratch)


TLS = r'''
import json, os, ssl, gate_confine
gate_confine.confine_gate(sys.argv[1])
# As the HTTP clients do (httpcore's default context): the bundle named, loaded
# now, an error if it cannot be read. With no cafile, OpenSSL ignores one it cannot read.
ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
print(json.dumps({"ok": True}))
'''

def _a_ca_bundle():
    import ssl
    try:
        import certifi
        return certifi.where()
    except ImportError:
        pass
    paths = ssl.get_default_verify_paths()
    for p in (paths.cafile, paths.openssl_cafile, "/etc/ssl/certs/ca-certificates.crt"):
        if p and os.path.isfile(p): return p
    pytest.skip("no CA bundle here to copy")

def test_the_confined_gate_still_reads_the_certificates_tls_trusts(tmp_path):
    """A proxy's CA bundle named by SSL_CERT_FILE lives wherever the proxy put
    it: here, a copy outside everything else the gate keeps."""
    work = tmp_path / "work"; work.mkdir()
    bundle = tmp_path / "proxy" / "ca-bundle.crt"; bundle.parent.mkdir()
    shutil.copy(_a_ca_bundle(), bundle)
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(ROOT)!r})\n" + TLS, str(work)],
                       capture_output=True, text=True, timeout=60, cwd=str(ROOT),
                       env=dict(os.environ, TMPDIR=str(tmp_path), SSL_CERT_FILE=str(bundle)))
    assert r.returncode == 0, r.stderr


MESSAGE = {"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
           "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn", "stop_sequence": None,
           "usage": {"input_tokens": 1, "output_tokens": 1}}

def _stored_login(conf, base_url, expires_at):
    """A profile as `ant auth login` leaves one: its config, and credentials
    that only their owner may read."""
    (conf / "configs").mkdir(parents=True); (conf / "credentials").mkdir(mode=0o700)
    (conf / "configs" / "default.json").write_text(json.dumps(
        {"base_url": base_url, "authentication": {"type": "user_oauth", "client_id": "c"}}))
    stored = conf / "credentials" / "default.json"
    stored.write_text(json.dumps({"type": "oauth_token", "access_token": "stale", "expires_at": expires_at,
                                  "refresh_token": "r0"}))
    stored.chmod(0o600)
    return stored

def test_a_stored_login_signs_in_and_refreshes_from_the_confined_gate(tmp_path):
    """`ant auth login` (README): the SDK reads the profile once the gate is
    confined, finds its token stale, refreshes it, and replaces the
    credentials file with the new one, all from inside the confinement."""
    pytest.importorskip("anthropic")
    srv = _serve((200, {"access_token": "fresh", "expires_in": 3600, "refresh_token": "rotated"}), (200, MESSAGE))
    conf = tmp_path / "anthropic"
    stored = _stored_login(conf, f"http://127.0.0.1:{srv.server_port}", expires_at=1)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    env.update(ANTHROPIC_CONFIG_DIR=str(conf), TMPDIR=str(tmp_path))
    try:
        r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(tmp_path / "w"),
                            "--model", "m"], capture_output=True, text=True, timeout=120, env=env)
    finally: srv.shutdown(); srv.server_close()
    assert r.returncode == 0 and "gate: confined (Landlock)" in r.stderr, r.stderr
    assert [(p, a) for p, a, _ in srv.seen] == [("/v1/oauth/token", None), ("/v1/messages", "Bearer fresh")]
    assert json.loads(stored.read_text())["refresh_token"] == "rotated"     # kept: the next run signs in with it
    assert os.listdir(conf / "credentials") == ["default.json"]            # and no temporary file beside it


def test_a_login_kept_outside_the_sdks_directory_stops_the_agent_before_any_refresh(tmp_path):
    """A profile may keep its credentials elsewhere (credentials_path), where
    the confined gate cannot read them. The SDK reads them before it would
    refresh, so the agent stops with the token endpoint never asked, and the
    stored refresh token is still the one that works."""
    pytest.importorskip("anthropic")
    srv = _serve()
    conf = tmp_path / "anthropic"
    _stored_login(conf, f"http://127.0.0.1:{srv.server_port}", expires_at=1)
    elsewhere = tmp_path / "elsewhere"; elsewhere.mkdir(mode=0o700)
    moved = elsewhere / "creds.json"; os.replace(conf / "credentials" / "default.json", moved)
    profile = json.loads((conf / "configs" / "default.json").read_text())
    profile["authentication"]["credentials_path"] = str(moved)
    (conf / "configs" / "default.json").write_text(json.dumps(profile))
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    env.update(ANTHROPIC_CONFIG_DIR=str(conf), TMPDIR=str(tmp_path))
    try:
        r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(tmp_path / "w"),
                            "--model", "m"], capture_output=True, text=True, timeout=120, env=env)
    finally: srv.shutdown(); srv.server_close()
    assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    assert "cannot call the API" in r.stderr and str(moved) in r.stderr, r.stderr
    assert srv.seen == []
    assert json.loads(moved.read_text())["refresh_token"] == "r0"


def test_a_workdir_holding_the_stored_login_is_refused_before_anything_runs(tmp_path):
    pytest.importorskip("anthropic")
    work = tmp_path / "w"; conf = work / ".anthropic"
    _stored_login(conf, "https://api.anthropic.com", expires_at=1)
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    env.update(ANTHROPIC_CONFIG_DIR=str(conf), TMPDIR=str(tmp_path))
    r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(work),
                        "--model", "m"], capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    assert f"not starting: the workdir {os.path.realpath(work)} overlaps {os.path.realpath(conf)}," in r.stderr


LOGIN_REACH = r'''
import json, os, gate_confine
conf = os.environ["ANTHROPIC_CONFIG_DIR"]
gate_confine.confine_gate(sys.argv[1], anthropic=True)
reach = {}
def attempt(name, fn):
    try: fn(); reach[name] = "done"
    except PermissionError: reach[name] = "refused"
attempt("read the profile", lambda: open(conf + "/configs/default.json").read())
attempt("read the credentials", lambda: open(conf + "/credentials/default.json").read())
def replace():
    with open(conf + "/credentials/.new", "w") as f: f.write("{}")
    os.replace(conf + "/credentials/.new", conf + "/credentials/default.json")
attempt("replace the credentials", replace)
attempt("change the profile", lambda: open(conf + "/configs/default.json", "w"))
attempt("add a profile", lambda: open(conf + "/configs/other.json", "x"))
attempt("choose another profile", lambda: open(conf + "/active_config", "x"))
attempt("remove the profile", lambda: os.remove(conf + "/configs/default.json"))
attempt("move the credentials directory", lambda: os.rename(conf + "/credentials", conf + "/moved"))
print(json.dumps(reach))
'''

def test_the_confined_gate_may_replace_the_stored_credentials_but_not_where_they_go(tmp_path):
    """Where the model's credentials are sent comes from the profile's config
    (base_url), never from the credentials file: so the gate keeps the one it
    must replace, and cannot write the config, add or choose a profile."""
    conf = tmp_path / "anthropic"; _stored_login(conf, "https://api.anthropic.com", expires_at=1)
    work = tmp_path / "work"; work.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    env.update(ANTHROPIC_CONFIG_DIR=str(conf), TMPDIR=str(tmp_path))
    r = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {str(ROOT)!r})\n" + LOGIN_REACH,
                        str(work)], capture_output=True, text=True, timeout=60, cwd=str(ROOT), env=env)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {
        "read the profile": "done", "read the credentials": "done", "replace the credentials": "done",
        "change the profile": "refused", "add a profile": "refused", "choose another profile": "refused",
        "remove the profile": "refused", "move the credentials directory": "refused"}


def test_the_stored_login_is_kept_only_when_the_sdk_would_read_it(tmp_path, monkeypatch):
    conf = tmp_path / "anthropic"; (conf / "credentials").mkdir(parents=True)
    token = tmp_path / "identity.jwt"; token.write_text("t")
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(conf))
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN_FILE", str(token))
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"): monkeypatch.delenv(k, raising=False)
    kept = lambda **kw: dict(gate_confine.plan(str(tmp_path / "scratch"), **kw))
    rules = kept(anthropic=True)
    assert rules[str(conf)] == gate_confine.READ_FILE | gate_confine.READ_DIR
    G = gate_confine                       # what replacing a file takes, and nothing else
    assert rules[str(conf / "credentials")] == G.READ_FILE | G.READ_DIR | G.WRITE_FILE | G.MAKE_REG | G.REMOVE_FILE
    assert rules[str(token)] == gate_confine.READ_FILE
    assert not {str(conf), str(token)} & set(kept())                          # another backend: none of it
    assert gate_confine.conflicts(str(tmp_path), list(rules.items()))         # a workdir holding it is refused
    assert gate_confine.conflicts(str(conf / "credentials" / "w"), list(rules.items()))      # or inside it
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):                 # the SDK reads none of it then
        monkeypatch.setenv(key, "k")
        assert not {str(conf), str(token)} & set(kept(anthropic=True))
        monkeypatch.delenv(key)


def test_the_gate_looks_for_the_stored_login_where_the_sdk_keeps_it(tmp_path, monkeypatch):
    """gate_confine copies the SDK's rule for where its login is kept; when
    the SDK moves it, this fails, rather than the gate silently granting a
    directory the SDK no longer reads."""
    pytest.importorskip("anthropic")
    from anthropic.lib.credentials import _constants as sdk
    monkeypatch.setenv("HOME", str(tmp_path))
    for where in (None, str(tmp_path / "elsewhere")):
        if where: monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", where)
        else: monkeypatch.delenv("ANTHROPIC_CONFIG_DIR", raising=False)
        base = gate_confine.sdk_config_dir()
        assert base == str(sdk._config_dir())
        assert str(sdk._credentials_file_path("default").parent) == os.path.join(base, "credentials")
        assert str(sdk._config_file_path("default")).startswith(base + "/")
