from dataclasses import replace

import pytest

import tests.support  # noqa: F401
from cross_sangha import GlobalNullifierSet, aggregate, publish, verify
from doctor import observe as doctor_observe
from ledger import Ledger
from mirror import Adversary, Class
from signing import (HMACSigner, PublicVerifier, SharedSecretVerifier,
                     default_signer, verifier_for)
from to_coq_witness import Attestation, Record
from trajectory import TrajectoryAttestation

G = "0" * 64

def signed_traj(signer, action_digest, verdict="LAWFUL"):
    a = TrajectoryAttestation(signer.id, (0,), action_digest, verdict)
    return replace(a, signature=signer.sign(a.payload()).hex())

def signed_att(signer, status="coqc-pass", action_digest="d", verdict="LAWFUL", vow_hash="v"):
    # Bound by default to what record() records: action "d", LAWFUL, vow "v".
    a = Attestation("g", "guard", "b", 0, "i", "c", "o", signer.id, status,
                    action_digest=action_digest, vow_hash=vow_hash, verdict=verdict)
    return replace(a, signature=signer.sign(a.payload()).hex())

def record(action_digest="d", traj="", att=""):
    return Record(0, G, att, G, action_digest, (), traj, "c", "LAWFUL", "G", 2.0, "v")

def ledger_with(signer):
    L = Ledger("t"); L.register_verifier(verifier_for(signer)); return L

# --- the ledger checks every stored signature ---------------------------------

def test_valid_attestations_verify():
    s = default_signer("S"); L = ledger_with(s)
    a, t = signed_att(s), signed_traj(s, "d")
    L.store_attestation(a); L.store_attestation(t)
    L.append(record(traj=t.attestation_hash(), att=a.attestation_hash()))
    assert L.verify_integrity()

@pytest.mark.parametrize("damage", ["tamper", "strip", "unregistered", "wrong_key_slot"])
def test_a_bad_signature_breaks_integrity(damage):
    s = default_signer("S"); L = ledger_with(s); a = signed_att(s)
    if damage == "tamper":
        sig = bytearray(bytes.fromhex(a.signature)); sig[0] ^= 1
        a = replace(a, signature=sig.hex())
    elif damage == "strip":
        a = replace(a, signature="")
    elif damage == "unregistered":
        L.verifiers.clear()
    L.store_attestation(a)
    if damage == "wrong_key_slot":
        L.attestations["f" * 64] = L.attestations.pop(a.attestation_hash())
    assert not L.verify_integrity()

def test_a_trajectory_attestation_must_be_for_the_recorded_action():
    s = default_signer("S"); L = ledger_with(s); t = signed_traj(s, "action-A")
    L.store_attestation(t)
    L.append(record(action_digest="action-B", traj=t.attestation_hash()))
    assert not L.verify_integrity()

def test_a_record_must_cite_a_cosigner_attestation():
    s = default_signer("S"); L = ledger_with(s); t = signed_traj(s, "d")
    L.store_attestation(t)
    L.append(record(att=t.attestation_hash()))
    assert not L.verify_integrity()

def test_first_record_must_link_to_genesis():
    L = Ledger("t"); L.records.append(replace(record(), prev_hash="1" * 64))
    assert not L.verify_integrity()

def test_a_signer_cannot_be_re_registered_under_another_key():
    L = Ledger("t"); L.register_verifier(verifier_for(default_signer("S")))
    with pytest.raises(ValueError):
        L.register_verifier(verifier_for(default_signer("S")))

# --- signers are separate parties -----------------------------------------------

def test_fallback_signers_do_not_share_a_key(without):
    without("dilithium-py")
    a, b = default_signer("A"), default_signer("B")
    assert a.scheme == b.scheme == "hmac-sha256"
    assert not verifier_for(a).verify(b"m", b.sign(b"m"))

def test_hmac_has_no_public_key():
    s = HMACSigner("H", b"k" * 32)
    with pytest.raises(TypeError): s.public_bytes()
    with pytest.raises(ValueError): PublicVerifier("H", "hmac-sha256", b"k" * 32)
    v = verifier_for(s)
    assert isinstance(v, SharedSecretVerifier) and not v.publicly_verifiable

def test_doctor_reports_degraded_signing_and_unchecked_certificates():
    s = HMACSigner("H", b"k" * 32); L = ledger_with(s)
    L.store_attestation(signed_att(s, status="coqc-unavailable"))
    _, findings = doctor_observe(L)
    degraded = {f.name for f in findings if f.level == "DEGRADED"}
    assert degraded == {"shared_secret_signers", "unchecked_certificates"}
    assert all(f.next_step for f in findings if f.level == "DEGRADED")

# --- cross-sangha ---------------------------------------------------------------

def sangha_ledger():
    L = Ledger("alpha"); L.records.append(record()); return L

def test_one_key_cannot_speak_for_three_sanghas():
    k = default_signer("alpha")
    atts = [publish(sangha_ledger(), sid, "c", k, 0) for sid in ("alpha", "beta", "gamma")]
    r = aggregate(atts, {"alpha": verifier_for(k)})
    assert r["n_rejected"] == 2
    assert all(s == {"alpha"} for s in r["signers"].values())

def test_one_key_cannot_be_registered_for_two_sanghas():
    k = default_signer("alpha")
    v_alpha = verifier_for(k)
    v_beta = PublicVerifier("beta", k.scheme, k.public_bytes()) if k.publicly_verifiable \
        else SharedSecretVerifier(HMACSigner("beta", k._key))
    with pytest.raises(ValueError, match="share one key"):
        aggregate([], {"alpha": v_alpha, "beta": v_beta})

def test_nullifier_root_is_checked():
    k = default_signer("alpha"); a = publish(sangha_ledger(), "alpha", "c", k, 0)
    bad = replace(a, nullifier_root="1" * 64, signature="")
    bad = replace(bad, signature=k.sign(bad.payload()).hex())
    ok, why = verify(bad, {"alpha": verifier_for(k)})
    assert not ok and "nullifier" in why

def test_a_replayed_attestation_is_not_credited_twice():
    k = default_signer("alpha"); a = publish(sangha_ledger(), "alpha", "c", k, 0)
    seen = GlobalNullifierSet(); vs = {"alpha": verifier_for(k)}
    assert aggregate([a], vs, seen)["n_unique"] == 1
    again = aggregate([a], vs, seen)
    assert again["n_unique"] == 0 and again["n_replayed"] == 1

# --- adversary transcripts --------------------------------------------------------

def test_transcripts_verify_with_the_adversarys_own_key_only():
    from guard import Guard
    k, other = default_signer("Adv"), default_signer("Other")
    adv = Adversary("Adv", k, b"s")
    for cid in ("c.a", "c.b", "c.c"):
        adv.register(Class(cid, "forbid exfiltrate", 1.0), lambda s, c: {"effects": []})
    adv.commit()
    g = Guard("G", Ledger("t"))
    for e in range(3): adv.next_engagement(g, bytes([e]) * 32, e)
    adv.reveal_index()
    assert adv.verify_transcript(verifier_for(k)) == (True, "ok")
    assert adv.verify_transcript(verifier_for(other))[0] is False

def test_a_key_registered_under_another_sanghas_name_is_refused():
    k = default_signer("alpha"); a = publish(sangha_ledger(), "beta", "c", k, 0)
    ok, why = verify(a, {"beta": verifier_for(k)})
    assert not ok and "registered under" in why

def test_a_transcript_verifier_must_be_the_adversarys():
    k = default_signer("Adv"); adv = Adversary("Adv", k, b"s")
    adv.register(Class("c.a", "forbid exfiltrate", 1.0), lambda s, c: {"effects": []})
    adv.commit(); adv.reveal_index()
    same_key_wrong_name = (PublicVerifier("Other", k.scheme, k.public_bytes()) if k.publicly_verifiable
                           else SharedSecretVerifier(HMACSigner("Other", k._key)))
    ok, why = adv.verify_transcript(same_key_wrong_name)
    assert not ok and "not 'Adv'" in why
