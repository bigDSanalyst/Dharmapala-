"""Checkpoint anchoring, driven through its real entry point.

The rule is the one syndicate-genesis's faultkit enforces: a tool whose data
source was unavailable must not exit 0, and the harness never simulates the
tool, it breaks what is underneath it. Here that is the ots CLI, replaced on
PATH by a fake that can succeed, confirm, be unreachable, lie about a digest,
or fail to execute at all."""
import hashlib, json, os, shutil, stat, subprocess, sys
from pathlib import Path

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
from compression import compress
from tests.test_compression import BEFORE, Rig, binary  # noqa: F401  (fixture)

FAKE_OTS = r'''#!{python}
import hashlib, os, sys
mode = os.environ.get("FAKE_OTS_MODE", "ok")
cmd, path = sys.argv[1], sys.argv[-1]
down = ("Calendar https://a.pool.opentimestamps.org: Tunnel connection failed: 403 Forbidden\n")
if cmd == "stamp":
    if mode == "down": sys.stderr.write(down + "Failed to create timestamp\n"); sys.exit(1)
    open(path + ".ots", "w").write("stub"); sys.exit(0)
if cmd == "upgrade":
    if mode == "down": sys.stderr.write(down); sys.exit(1)
    sys.stderr.write("Calendar https://a.pool.opentimestamps.org: Pending confirmation in Bitcoin blockchain\n")
    sys.exit(0 if os.environ.get("FAKE_OTS_CONFIRM") else 1)
if cmd == "info":
    target = path[:-4]
    digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
    if mode == "wrongdigest": digest = "0" * 64
    print("File sha256 hash: " + digest)
    if os.environ.get("FAKE_OTS_CONFIRM"): print("verify BitcoinBlockHeaderAttestation(900123)")
    sys.exit(0)
sys.exit(2)
'''

@pytest.fixture(scope="module")
def ledger_file(binary, tmp_path_factory):
    d = tmp_path_factory.mktemp("ledger"); path = d / "l.json"
    r = Rig(path=str(path))
    for s in BEFORE: r.run(s, binary)
    compress(r.L, 2, r.compressor); compress(r.L, 3, r.compressor)
    return path, r

def fake_bin(tmp_path, broken=False):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    ots = b / "ots"
    ots.write_text("#!/nonexistent/interpreter\n" if broken else FAKE_OTS.format(python=sys.executable))
    ots.chmod(ots.stat().st_mode | stat.S_IEXEC)
    return b

def tool(cmd, ledger, anchors, bin_dir=None, **env):
    # Only the ots under test is reachable: exec keeps searching PATH past a
    # shim it cannot run, so a real ots later on PATH would stand in for a broken one.
    path = os.pathsep.join(p for p in os.environ["PATH"].split(os.pathsep) if not (Path(p) / "ots").exists())
    if bin_dir is not None: path = f"{bin_dir}{os.pathsep}{path}"
    e = {**os.environ, "PATH": path, **env}
    return subprocess.run([sys.executable, str(ROOT / "anchoring.py"), cmd, "--ledger", str(ledger),
                           "--dir", str(anchors)], capture_output=True, text=True, env=e, timeout=120)

def log(anchors): return [json.loads(l) for l in (anchors / "log.jsonl").read_text().splitlines()]

# --- the calendars answered ---------------------------------------------------------------

def test_run_records_and_stamps_every_checkpoint(ledger_file, tmp_path):
    path, r = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    res = tool("run", path, a, b)
    assert res.returncode == 0, res.stdout + res.stderr
    entries = log(a)
    assert [e["checkpoint_hash"] for e in entries] == [c.hash() for c in r.L.checkpoints]
    assert all(e["status"] == "pending" for e in entries)
    assert tool("run", path, a, b).returncode == 0 and len(log(a)) == 2        # idempotent
    assert tool("verify", path, a, b).returncode == 0

def test_upgrade_records_the_bitcoin_block(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    res = tool("upgrade", path, a, b, FAKE_OTS_CONFIRM="1")
    assert res.returncode == 0, res.stdout
    assert all(e["status"] == "confirmed" and e["height"] == 900123 for e in log(a))

def test_pending_is_a_real_answer(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    res = tool("upgrade", path, a, b)
    assert res.returncode == 0 and "not yet in a Bitcoin block" in res.stdout

# --- the calendars did not answer: never exit 0 on "upgrade" --------------------------------

def test_unreachable_calendars_on_run_record_and_defer(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    res = tool("run", path, a, b, FAKE_OTS_MODE="down")
    assert res.returncode == 0                                   # recording succeeded (mold row 74)
    assert all(e["status"] == "unsubmitted" for e in log(a))

def test_unreachable_calendars_on_upgrade_of_unsubmitted_anchors(ledger_file, tmp_path):
    """Mold row 76: exit 0 here would mean nothing established and a green check."""
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b, FAKE_OTS_MODE="down")
    res = tool("upgrade", path, a, b, FAKE_OTS_MODE="down")
    assert res.returncode == 2, res.stdout

def test_unreachable_calendars_on_upgrade_of_pending_anchors(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    res = tool("upgrade", path, a, b, FAKE_OTS_MODE="down")
    assert res.returncode == 2 and "NOT 'not yet confirmed'" in res.stdout

def test_no_ots_at_all(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"
    assert tool("run", path, a).returncode == 0
    assert tool("upgrade", path, a).returncode == 2

def test_an_ots_that_will_not_run_needs_a_human(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"
    tool("run", path, a, fake_bin(tmp_path))
    broken = tmp_path / "broken"; broken.mkdir(); fake_bin(broken, broken=True)
    res = tool("upgrade", path, a, broken / "bin")
    assert res.returncode == 1 and "not a network problem" in res.stdout

def test_a_stale_unsubmitted_anchor_needs_a_human(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b, FAKE_OTS_MODE="down")
    entries = log(a); entries[0]["created"] = "2026-01-01T00:00:00Z"
    (a / "log.jsonl").write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in entries))
    assert tool("run", path, a, b, FAKE_OTS_MODE="down").returncode == 1

@pytest.mark.skipif(shutil.which("ots") is None, reason="the real ots CLI is not installed")
def test_the_real_ots_never_exits_0_having_established_nothing(ledger_file, tmp_path):
    """Whatever this machine's network allows: exit 0 only with every anchor
    actually submitted. (In this project's sandbox the calendars answer 403.)"""
    path, _ = ledger_file; a = tmp_path / "anchors"
    real = Path(shutil.which("ots")).parent
    tool("run", path, a, real)
    res = tool("upgrade", path, a, real)
    assert res.returncode != 0 or all(e["status"] != "unsubmitted" for e in log(a)), res.stdout

# --- verify ----------------------------------------------------------------------------------

@pytest.mark.parametrize("damage", ["export", "chain", "digest", "foreign", "unanchored"])
def test_verify_refuses_damage(ledger_file, tmp_path, binary, damage):
    path, r = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    env = {}
    if damage == "export":
        f = a / log(a)[0]["file"]; f.write_text(f.read_text().replace('"cut_epoch":2', '"cut_epoch":9'))
    elif damage == "chain":
        entries = log(a); entries[1]["prev"] = "0" * 64
        (a / "log.jsonl").write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in entries))
    elif damage == "digest":
        env["FAKE_OTS_MODE"] = "wrongdigest"
    elif damage == "foreign":            # anchors from a different ledger
        other = tmp_path / "other.json"; o = Rig(path=str(other))
        for s in BEFORE: o.run(s, binary)
        compress(o.L, 2, o.compressor)
        path = other
    else:                                # a checkpoint the ledger holds, never anchored
        r2 = Rig(path=str(tmp_path / "grown.json"))
        for s in BEFORE: r2.run(s, binary)
        compress(r2.L, 2, r2.compressor)
        a2 = tmp_path / "a2"; tool("run", tmp_path / "grown.json", a2, b)
        compress(r2.L, 3, r2.compressor)
        path, a = tmp_path / "grown.json", a2
    res = tool("verify", path, a, b, **env)
    assert res.returncode == 1, res.stdout

# --- verify.py check --anchors ----------------------------------------------------------------

def check(ledger, pins, anchors, bin_dir):
    e = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    r = subprocess.run([sys.executable, str(ROOT / "verify.py"), "check", str(ledger), "--pins", str(pins),
                        "--anchors", str(anchors), "--json"], capture_output=True, text=True, env=e, timeout=300)
    assert "Traceback" not in r.stdout + r.stderr, r.stdout + r.stderr
    return r.returncode, json.loads(r.stdout)

@pytest.fixture
def pinned(ledger_file, tmp_path):
    path, r = ledger_file
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({sid: v.key_id() for sid, v in r.L.verifiers.items()}))
    return path, pins

def test_verify_passes_with_its_anchors_and_says_which_are_unconfirmed(pinned, tmp_path):
    path, pins = pinned; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    code, out = check(path, pins, a, b)
    assert code == 0 and out["verified"], out
    looks = [f["reason"] for f in out["findings"] if f["name"] == "anchor"]
    assert looks == ["anchor #0001 is pending, not yet confirmed in Bitcoin",
                     "anchor #0002 is pending, not yet confirmed in Bitcoin"]
    tool("upgrade", path, a, b, FAKE_OTS_CONFIRM="1")
    code, out = check(path, pins, a, b)
    assert code == 0 and not [f for f in out["findings"] if f["name"] == "anchor"]

@pytest.mark.parametrize("damage", ["no log", "export", "unanchored"])
def test_verify_fails_on_anchors_that_do_not_hold(pinned, tmp_path, damage):
    path, pins = pinned; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    if damage == "no log":
        a.mkdir()
    else:
        tool("run", path, a, b)
        entries = log(a)
        if damage == "export":
            f = a / entries[0]["file"]; f.write_text(f.read_text().replace('"cut_epoch":2', '"cut_epoch":9'))
        else:                                   # the last checkpoint's anchor never happened
            (a / "log.jsonl").write_text(json.dumps(entries[0], sort_keys=True, separators=(",", ":")) + "\n")
    code, out = check(path, pins, a, b)
    assert code == 1 and not out["verified"]
    assert any(r.startswith("anchors:") for r in out["reasons"]), out["reasons"]

# Each check in `verify` alone: the damage above trips several at once.

def _rewrite(a, entries):
    (a / "log.jsonl").write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in entries))

def test_verify_refuses_an_export_whose_bytes_changed_but_not_its_checkpoint(ledger_file, tmp_path):
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    f = a / log(a)[-1]["file"]; f.write_text(json.dumps(json.loads(f.read_text()), indent=1))
    res = tool("verify", path, a, b)
    assert res.returncode == 1 and "export digest mismatch" in res.stdout, res.stdout

def test_verify_refuses_an_export_rewritten_together_with_its_entry(ledger_file, tmp_path):
    """The last entry's export and its digest both rewritten: the chain and the
    digest hold, and only the checkpoint's own hash shows the swap."""
    path, _ = ledger_file; a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", path, a, b)
    entries = log(a); f = a / entries[-1]["file"]
    f.write_text(f.read_text().replace('"cut_epoch":3', '"cut_epoch":9'))
    entries[-1]["file_sha256"] = hashlib.sha256(f.read_bytes()).hexdigest(); _rewrite(a, entries)
    res = tool("verify", path, a, b)
    assert res.returncode == 1 and "not the checkpoint the log names" in res.stdout, res.stdout

def test_verify_refuses_an_anchor_for_a_checkpoint_the_ledger_does_not_hold(binary, tmp_path):
    """Every checkpoint of the ledger is anchored, and one more is: anchors
    taken from a later copy of it, checked against an earlier one."""
    r = Rig(path=str(tmp_path / "l.json"))
    for s in BEFORE: r.run(s, binary)
    compress(r.L, 2, r.compressor)
    early = tmp_path / "early.json"; early.write_text((tmp_path / "l.json").read_text())
    compress(r.L, 3, r.compressor)
    a = tmp_path / "anchors"; b = fake_bin(tmp_path)
    tool("run", tmp_path / "l.json", a, b)
    res = tool("verify", early, a, b)
    assert res.returncode == 1 and "not in this ledger" in res.stdout, res.stdout
