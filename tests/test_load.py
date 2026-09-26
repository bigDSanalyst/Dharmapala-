"""A persisted ledger loads back into the same objects and verifies the same
way, and loading it does not make it trusted."""
import json, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from compression import compress
from doctor import observe as doctor_observe
from fraud import find_fraud
from ledger import KeyMismatch, Ledger
from signing import HMACSigner, SharedSecretVerifier, default_signer, verifier_for
from tests.test_compression import AFTER, BEFORE, Rig, binary  # noqa: F401  (fixture)
from tests.test_fraud import doctored

def built(binary, compressed=True):
    d = tempfile.mkdtemp(); path = os.path.join(d, "l.json")
    r = Rig(path=path)
    for s in BEFORE: r.run(s, binary)
    if compressed:
        compress(r.L, 2, r.compressor); r.run(AFTER[0], binary)
    return r, path

def pins(r):
    return {sid: v.key_id() for sid, v in r.L.verifiers.items()}

def test_a_loaded_ledger_is_the_same_ledger(binary):
    r, path = built(binary)
    L = Ledger.load(path, pinned=pins(r))
    assert L.verify_integrity()
    assert (L.records, L.audits, L.checkpoints) == (r.L.records, r.L.audits, r.L.checkpoints)
    assert L.attestations == r.L.attestations
    assert (L.head_hash(), L.audit_head(), L.next_record_index()) == \
        (r.L.head_hash(), r.L.audit_head(), r.L.next_record_index())
    assert L.carried() == r.L.carried() and L.trajectory_head() == r.L.trajectory_head()

def test_a_loaded_ledger_keeps_going(binary):
    r, path = built(binary)
    L = Ledger.load(path, pinned=pins(r))
    r.L = L; r.g.ledger = L                     # the guard continues on the loaded ledger
    r.run(AFTER[1], binary)
    assert L.verify_integrity() and Ledger.load(path, pinned=pins(r)).verify_integrity()

@pytest.mark.parametrize("edit", ["merit", "verdict", "summary", "drop_record"])
def test_an_edited_file_does_not_verify(binary, edit):
    r, path = built(binary)
    data = json.load(open(path))
    if edit == "merit": data["records"][0]["punya_delta"] = 99.0
    elif edit == "verdict": data["records"][0]["verdict_kind"] = "LAWFUL" if data["records"][0]["verdict_kind"] == "LEARNING" else "LEARNING"
    elif edit == "summary": data["checkpoints"][0]["summary_json"] = data["checkpoints"][0]["summary_json"].replace('"refused":1', '"refused":0')
    else: data["records"].pop(0)
    json.dump(data, open(path, "w"))
    assert not Ledger.load(path, pinned=pins(r)).verify_integrity()

def test_a_swapped_key_is_refused_when_pinned(binary):
    """Someone rewrites the file under their own key and re-signs: pinning
    catches it; without pins, doctor says the file vouched for itself."""
    r, path = built(binary, compressed=False)
    thief = default_signer("Co")
    data = json.load(open(path))
    if not thief.publicly_verifiable: pytest.skip("needs ml-dsa-65 public keys")
    data["verifiers"]["Co"]["public"] = thief.public_bytes().hex()
    json.dump(data, open(path, "w"))
    with pytest.raises(KeyMismatch):
        Ledger.load(path, pinned=pins(r))
    L = Ledger.load(path)
    _, findings = doctor_observe(L)
    assert "keys_from_the_file" in {f.name for f in findings if f.level == "LOOK"}

def test_pinned_keys_raise_no_self_vouching_finding(binary):
    r, path = built(binary)
    _, findings = doctor_observe(Ledger.load(path, pinned=pins(r)))
    assert "keys_from_the_file" not in {f.name for f in findings}

def test_a_conviction_survives_a_reload(binary):
    r, path = built(binary, compressed=False)
    cp, archive = compress(r.L, 3, r.compressor)
    bad, ba = doctored(r, cp, archive, tamper=lambda k, s: s if k != 1 else {**s, "outcomes": s["outcomes"] + "1"})
    r.L.checkpoints[-1] = bad; r.L._persist()
    proof, _ = find_fraud(ba, bad)
    r.L.dispute(0, proof)
    L = Ledger.load(path, pinned=pins(r))
    assert L.convicted() == [0] and not L.verify_integrity()

def test_shared_secret_signers_must_be_supplied(binary, without):
    without("dilithium-py")
    r, path = built(binary, compressed=False)
    assert not Ledger.load(path).verify_integrity()          # no key to read from the file
    extras = [v for v in r.L.verifiers.values()]
    assert all(isinstance(v, SharedSecretVerifier) for v in extras)
    assert Ledger.load(path, extra_verifiers=extras).verify_integrity()

def test_only_the_v2_format_loads(tmp_path):
    p = tmp_path / "old.json"; p.write_text(json.dumps({"sangha_id": "x", "records": []}))
    with pytest.raises(ValueError, match="v2"): Ledger.load(str(p))
