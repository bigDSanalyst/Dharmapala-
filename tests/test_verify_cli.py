"""verify.py through its real entry point. A pass must mean: every signer
pinned, every chain, signature and checkpoint verified, nothing BLOCK or
DEGRADED. Every other outcome exits 1 with a named reason, never a traceback."""
import json, os, subprocess, sys
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
from compression import compress
from fraud import find_fraud
from tests.test_compression import AFTER, BEFORE, Rig, binary  # noqa: F401  (fixture)
from tests.test_fraud import doctored

def cli(*args, **env):
    r = subprocess.run([sys.executable, str(ROOT / "verify.py"), *map(str, args)],
                       capture_output=True, text=True, timeout=300, env={**os.environ, **env})
    assert "Traceback" not in r.stdout + r.stderr, r.stdout + r.stderr
    return r

@pytest.fixture
def ledger(binary, tmp_path):
    path = tmp_path / "l.json"; r = Rig(path=str(path))
    for s in BEFORE: r.run(s, binary)
    compress(r.L, 2, r.compressor); r.run(AFTER[0], binary)
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({sid: v.key_id() for sid, v in r.L.verifiers.items()}))
    return r, path, pins

def test_a_pinned_verified_ledger_passes(ledger):
    r, path, pins = ledger
    res = cli("check", path, "--pins", pins)
    assert res.returncode == 0 and res.stdout.strip().endswith("VERIFIED"), res.stdout

def test_keys_prints_the_ids_check_expects(ledger):
    r, path, pins = ledger
    res = cli("keys", path, "--json")
    assert res.returncode == 0 and json.loads(res.stdout) == json.loads(pins.read_text())

def test_json_output_is_machine_readable(ledger):
    r, path, pins = ledger
    out = json.loads(cli("check", path, "--pins", pins, "--json").stdout)
    assert out["verified"] is True and out["reasons"] == []
    assert {f["name"] for f in out["findings"]} >= {"structural"}

def test_unpinned_signers_fail(ledger):
    r, path, pins = ledger
    res = cli("check", path)
    assert res.returncode == 1 and "no pinned key" in res.stdout

def test_a_pin_for_a_signer_not_in_the_ledger_fails(ledger):
    r, path, pins = ledger
    res = cli("check", path, "--pins", pins, "--pin", "Ghost=" + "0" * 64)
    assert res.returncode == 1 and "Ghost" in res.stdout

def test_a_swapped_key_fails(ledger):
    r, path, pins = ledger
    res = cli("check", path, "--pins", pins, "--pin", "Co=" + "f" * 64)
    assert res.returncode == 1 and "not the pinned one" in res.stdout

@pytest.mark.parametrize("edit", ["merit", "summary"])
def test_an_edited_ledger_fails(ledger, edit):
    r, path, pins = ledger
    data = json.loads(path.read_text())
    if edit == "merit": data["records"][0]["punya_delta"] = 99.0
    else: data["checkpoints"][0]["summary_json"] = data["checkpoints"][0]["summary_json"].replace('"proven":', '"proven":9')
    path.write_text(json.dumps(data))
    res = cli("check", path, "--pins", pins)
    assert res.returncode == 1 and "BLOCK structural_failure" in res.stdout

def test_a_convicted_checkpoint_fails(binary, tmp_path):
    path = tmp_path / "l.json"; r = Rig(path=str(path))
    for s in BEFORE: r.run(s, binary)
    cp, archive = compress(r.L, 3, r.compressor)
    bad, ba = doctored(r, cp, archive, tamper=lambda k, s: s if k != 1 else {**s, "outcomes": s["outcomes"] + "1"})
    r.L.checkpoints[-1] = bad; r.L._persist()
    r.L.dispute(0, find_fraud(ba, bad)[0])
    pins = {sid: v.key_id() for sid, v in r.L.verifiers.items()}
    res = cli("check", path, *sum((["--pin", f"{k}={v}"] for k, v in pins.items()), []))
    assert res.returncode == 1 and "checkpoint_convicted" in res.stdout

def test_unchecked_certificates_fail(binary, tmp_path, monkeypatch):
    import to_coq_witness
    monkeypatch.setattr(to_coq_witness.Certificate, "check", staticmethod(lambda p, timeout=None: (None, "coqc not in PATH")))
    path = tmp_path / "l.json"; r = Rig(path=str(path))
    r.run(BEFORE[0], binary)
    pins = {sid: v.key_id() for sid, v in r.L.verifiers.items()}
    res = cli("check", path, *sum((["--pin", f"{k}={v}"] for k, v in pins.items()), []))
    assert res.returncode == 1 and "DEGRADED unchecked_certificates" in res.stdout

def test_a_shared_secret_ledger_cannot_be_verified_from_outside(binary, tmp_path, without):
    without("dilithium-py")
    path = tmp_path / "l.json"; r = Rig(path=str(path))
    r.run(BEFORE[0], binary)
    res = cli("check", path)
    assert res.returncode == 1 and "shared secret" in res.stdout

@pytest.mark.parametrize("content, why", [(None, "no such file"), ("not json", "JSONDecodeError"),
                                          ('{"sangha_id": "x"}', "v2")])
def test_a_file_that_is_not_a_ledger_is_named(tmp_path, content, why):
    p = tmp_path / "x.json"
    if content is not None: p.write_text(content)
    res = cli("check", p, "--pin", "A=" + "0" * 64)
    assert res.returncode == 1 and why in res.stdout, res.stdout

def test_a_malformed_pin_is_named(ledger):
    r, path, pins = ledger
    res = cli("check", path, "--pin", "nonsense")
    assert res.returncode == 1 and "SIGNER=KEYID" in res.stdout
