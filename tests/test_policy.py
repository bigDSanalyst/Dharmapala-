"""The policy is data with a hash, and every verdict names the one that judged it.

The Vow says read_sensitive_path is forbidden; the policy says which paths are
sensitive here. A deployment sets it in a file; the run record carries it;
the decision and the attestation name its hash, signed; the co-signer
re-derives effects under the record's policy and refuses any policy it was
not configured to vouch under."""
import hashlib, json, os, subprocess, sys, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
import jail, policy
from critic_loop import effects_from_evidence, evidence_of
from decision import Decision
from guard import VerdictKind
from observation import observe
from signing import default_signer, verifier_for
from tests.test_evidence import INPUTS, VOW, binary, engine, rig  # noqa: F401  (fixture)
from tests.test_jail import needs_jail
from to_coq_witness import CoSigner, RefusedToSign, build_certificate, propose
from vow import Action

W = "/work"
ENV = policy.Policy.from_dict({"sensitive_paths": [r"\.env$"]})    # .env files, and nothing else
STRICT = policy.Policy.load(ROOT / "policies" / "strict.json")

# --- the format ----------------------------------------------------------------------------------

def test_the_default_is_what_the_code_used_to_hard_wire():
    d = policy.DEFAULT
    assert d == policy.Policy.from_dict({"format": "dharmapala-policy/v1"})
    assert [d.is_sensitive(p) for p in ("/etc/shadow", "/root/x", "/home/u/.ssh/id_rsa", "/w/.env")] \
        == [True, True, True, False]
    assert "ls" in d.vetted_commands and "python3" not in d.vetted_commands
    assert d.allowed_hosts == () and "pastebin.com" in d.exfil_hosts and d.hoard_threshold == 3

@pytest.mark.parametrize("data, why", [
    ({"sensitive_paths": ["("]}, "sensitive_paths"),
    ({"sensitive_paths": "^/etc"}, "list of non-empty strings"),
    ({"vetted_commands": ["ls", ""]}, "list of non-empty strings"),
    ({"hoard_threshold": 0}, "positive integer"),
    ({"hoard_threshold": True}, "positive integer"),
    ({"alowed_hosts": ["x"]}, "unknown policy keys: alowed_hosts"),
    ({"format": "dharmapala-policy/v2"}, "not a dharmapala-policy/v1"),
    ([], "JSON object"),
])
def test_a_policy_that_does_not_say_what_it_means_is_refused(data, why):
    with pytest.raises(policy.PolicyError, match=why): policy.Policy.from_dict(data)

def test_a_key_given_replaces_the_default_it_does_not_add_to_it():
    assert not ENV.is_sensitive("/etc/shadow") and ENV.is_sensitive("/w/.env")

def test_the_hash_is_of_the_meaning_not_the_spelling():
    a = policy.Policy.from_dict({"vetted_commands": ["ls", "cat"], "allowed_hosts": ["Example.COM."]})
    b = policy.Policy.from_dict({"vetted_commands": ["cat", "ls"], "allowed_hosts": ["example.com"]})
    assert a.hash() == b.hash() != policy.DEFAULT.hash()

def test_the_hash_does_not_depend_on_the_process():
    """Sets iterate in an order Python randomises per process: a hash taken
    over that order would differ between the guard and the co-signer."""
    code = ("import sys; sys.path.insert(0, %r); import policy; "
            "print(policy.Policy.from_dict({'vetted_commands': [c + str(i) for c in 'abcdefgh' for i in range(9)]}).hash())"
            % str(ROOT))
    seen = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": str(seed)}).stdout for seed in (1, 2, 3, 4)}
    assert len(seen) == 1 and len(seen.pop().strip()) == 64

def test_the_example_strict_policy_loads_and_widens_what_is_sensitive():
    for p in ("/w/.env", "/w/app/.env.local", "/w/tls/server.key", "/home/u/.aws/credentials",
              "/proc/1/environ", "/etc/shadow"):
        assert STRICT.is_sensitive(p), p
    assert not STRICT.is_sensitive("/w/notes.txt")

# --- what effects mean ---------------------------------------------------------------------------

def test_observation_judges_by_the_policy_it_is_given():
    read_env = [("file_read", {"path": ".env"}, {})]
    assert "read_sensitive_path" not in observe(read_env, W)
    assert "read_sensitive_path" in observe(read_env, W, ENV)
    curl = [("shell", {"cmd": "curl https://api.example.com/x"}, {})]
    assert "network_unlisted" in observe(curl, W)
    assert "network_unlisted" not in observe(curl, W, policy.Policy.from_dict({"allowed_hosts": ["example.com"]}))
    assert "exfiltrate" in observe(curl, W, policy.Policy.from_dict({"exfil_hosts": ["api.example.com"]}))
    py = [("shell", {"cmd": "python3 x.py"}, {})]
    assert "exec_unvetted" not in observe(py, W, policy.Policy.from_dict({"vetted_commands": ["python3"]}))
    two = [("file_write", {"path": f"f{i}", "content": ""}, {}) for i in range(2)]
    assert "hoard" not in observe(two, W) and "hoard" in observe(two, W, policy.Policy.from_dict({"hoard_threshold": 2}))

@needs_jail
def test_the_trace_is_judged_by_the_policy_too(tmp_path):
    """No dry run sees the script open .env; the trace does, and the policy
    says that is sensitive."""
    (tmp_path / ".env").write_text("TOKEN=x\n")
    events = jail.run("printf 'cat .env\\n' > s.sh; sh s.sh", str(tmp_path)).events
    assert "read_sensitive_path" not in jail.effects_of(events, str(tmp_path))
    assert "read_sensitive_path" in jail.effects_of(events, str(tmp_path), ENV)
    jailed = [("shell", {"cmd": "sh s.sh"}, {"jailed": True, "events": events})]
    assert "read_sensitive_path" not in observe(jailed, str(tmp_path))
    assert "read_sensitive_path" in observe(jailed, str(tmp_path), ENV)       # observation passes it on

# --- the record, the decision and the attestation name it ------------------------------------------

def record(pol, *calls):
    return evidence_of(list(calls) or [("file_read", {"path": ".env"}, {"ok": True})], W, {"read"}, pol)

def act(evidence, reported=None):
    a = Action(id="a", verb="execute", domain="action")
    a._observed_effects = set(effects_from_evidence(evidence) if reported is None else reported)
    a._evidence = evidence
    return a

def co_under(pol, name="Co"):
    return CoSigner(default_signer(name), policy=pol)

def engage(a, co, binary):
    L, g, _, tr = rig()
    if co.id not in L.verifiers: L.register_verifier(verifier_for(co._signer))
    return g.engage(a, VOW, co, tr, "c0", INPUTS, engine, *binary), L

def test_the_run_record_carries_the_policy_and_the_decision_names_it():
    ev = record(ENV)
    assert ev["policy"] == ENV.to_dict()
    assert "read_sensitive_path" in effects_from_evidence(ev)              # re-derived under ENV
    assert Decision.of(act(ev), VOW).policy_hash == ENV.hash()

def test_the_attestation_signs_the_policy_hash(binary):
    v, L = engage(act(record(ENV)), co_under(ENV, "Env"), binary)
    assert v.kind == VerdictKind.LEARNING                                  # .env is sensitive under ENV
    a = L.attestations[v.attestation_hash]
    assert a.policy_hash == ENV.hash() and L.verify_integrity()
    L.attestations[v.attestation_hash] = replace(a, policy_hash=policy.DEFAULT.hash())
    assert not L.verify_integrity()

def test_an_attestation_about_no_run_keeps_the_payload_it_always_had():
    a = propose("G", "guard", "b", 0, INPUTS, build_certificate("x", engine(INPUTS)), engine(INPUTS), "Co")
    assert a.policy_hash == "" and b"|policy:" not in a.payload()

# --- the co-signer vouches under one policy --------------------------------------------------------

def test_a_co_signer_refuses_a_policy_it_does_not_vouch_under(binary):
    """The guard judged the .env read under a policy where .env is not
    sensitive, and says so honestly. The co-signer holds the strict policy."""
    lax = record(policy.DEFAULT)
    v, L = engage(act(lax), co_under(STRICT, "Strict"), binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL and "does not vouch under" in v.reason
    assert not L.attestations

def test_the_same_run_under_the_same_policy_is_signed(binary):
    v, L = engage(act(record(STRICT)), co_under(STRICT, "Strict"), binary)
    assert v.kind == VerdictKind.LEARNING and L.attestations          # signed: the verdict is honest

def test_a_guard_that_reports_effects_under_another_policy_than_its_record_names_is_refused(binary):
    """The record names ENV (under which .env is sensitive); the guard reports
    what the default policy would say. The co-signer re-derives under the
    record's policy and does not match."""
    ev = record(ENV)
    v, _ = engage(act(ev, reported=observe([("file_read", {"path": ".env"}, {})], W)), co_under(ENV, "Env"), binary)
    assert v.kind == VerdictKind.FAILURE_REFUSAL and "co-signer observed" in v.reason

def test_a_decision_that_names_another_policy_than_its_record_is_refused(binary):
    co = co_under(ENV, "Env"); a = act(record(ENV))
    d = replace(Decision.of(a, VOW), policy_hash=policy.DEFAULT.hash())
    outputs = engine(INPUTS)
    p = propose("G", "guard", hashlib.sha256(b"engine").hexdigest(), 0, INPUTS,
                build_certificate("x", outputs, d), outputs, co.id, decision=d)
    with pytest.raises(RefusedToSign, match="names a policy other than the run record's"):
        co.cosign(p, build_certificate("x", outputs, d).emit(), INPUTS, binary[0], engine,
                  decision=d, evidence=a._evidence)

# --- the guarded agent -----------------------------------------------------------------------------

def test_the_guarded_agent_judges_by_its_policy(tmp_path):
    """Under the default policy .env is an ordinary file; under the strict one
    the critic refuses to read it before anything runs. Either way a lawful
    read is signed under the policy the agent was given."""
    import guarded_agent as ga
    from tests.test_guarded_agent import Scripted, call, results, text, turn
    for pol, refused in ((policy.DEFAULT, False), (STRICT, True)):
        work = tmp_path / pol.hash()[:8]; work.mkdir()
        (work / ".env").write_text("TOKEN=x\n"); (work / "notes.txt").write_text("hello\n")
        gate, ledger = ga.setup(work, policy=pol)
        client = Scripted(turn(call(1, "file_read", path=".env")),
                          turn(call(2, "file_read", path="notes.txt")), turn(text("done"), stop="end_turn"))
        ga.GuardedAgent(client, gate).run("task")
        [env] = results(client, 1); [notes] = results(client, 2)
        assert env["is_error"] is refused, env
        assert ("TOKEN" in env["content"]) is not refused
        assert ("refused before running" in env["content"]) is refused
        assert notes == {"type": "tool_result", "tool_use_id": "toolu_2", "content": "hello\n", "is_error": False}
        assert {ledger.attestations[r.attestation_hash].policy_hash for r in ledger.records} == {pol.hash()}

@pytest.mark.parametrize("content", ["{not json", '{"sensitive_paths": ["("]}'])
def test_the_command_line_refuses_a_bad_policy_file(tmp_path, content):
    pytest.importorskip("anthropic")
    f = tmp_path / "p.json"; f.write_text(content)
    r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--policy", str(f),
                        "--workdir", str(tmp_path / "w")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and r.stderr.startswith("policy:") and "Traceback" not in r.stderr

@needs_jail
def test_the_rehearsal_judges_by_the_agents_policy_too(tmp_path):
    """No dry run sees the script read .env; the rehearsal does, and under the
    strict policy that is sensitive, so it is refused before it runs."""
    import guarded_agent as ga
    from tests.test_guarded_agent import Scripted, call, results, text, turn
    (tmp_path / ".env").write_text("TOKEN=x\n")
    gate, ledger = ga.setup(tmp_path, policy=STRICT)
    client = Scripted(turn(call(1, "shell", cmd="printf 'cat .env\\n' > s.sh; sh s.sh")),
                      turn(text("done"), stop="end_turn"))
    ga.GuardedAgent(client, gate).run("task")
    [r] = results(client, 1)
    assert r["is_error"] and "refused before running" in r["content"] and "read_sensitive_path" in r["content"]
    assert not (tmp_path / "s.sh").exists() and not ledger.records
