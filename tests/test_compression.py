"""Layer 7: compression is lossless and changes nothing the guard does.

Two ledgers run the same engagements; one is compressed part-way. Everything
the guard, adversary and drift monitor compute must come out the same, and
the erased entries must be recoverable from the archive and checkable against
the checkpoint without trusting whoever compressed."""
import hashlib, json, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
import compression
from compression import (Archive, CompressionError, compress, prove_inclusion,
                         verify_archive, verify_inclusion)
from eprocess import analyze, outcomes
from guard import Guard, VerdictKind
from ledger import Ledger
from mirror import Adversary, Class
from signing import default_signer, verifier_for
from to_coq_witness import CoSigner
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

VOW = parse_vow("""
vow T
  forbid exfiltrate forall action
  forbid hoard forall action
  trajectory t: never effect:exfiltrate after effect:read
""")

def engine(inputs):
    a, b, w = inputs["butterflies"][0]
    return {"butterflies": [{"a": a, "b": b, "w": w, "ea": (a + w * b) % 3329,
                             "eb": (a + (3329 - w) * b) % 3329}]}

@pytest.fixture(scope="module")
def binary():
    fd, path = tempfile.mkstemp(); os.write(fd, b"engine"); os.close(fd)
    yield path, hashlib.sha256(b"engine").hexdigest()
    os.remove(path)

class Rig:
    def __init__(self, path=None):
        self.L = Ledger("t", path=path); self.g = Guard("G", self.L)
        s_co, s_tr = default_signer("Co"), default_signer("Tr")
        self.compressor = default_signer("Compressor")
        for s in (s_co, s_tr, self.compressor): self.L.register_verifier(verifier_for(s))
        self.co, self.tr = CoSigner(s_co), TrajectoryCoSigner(s_tr)
    def run(self, step, binary):
        i, effects, cls = step
        a = Action(id=f"a{i}", verb="execute", domain="action"); a._observed_effects = set(effects)
        return self.g.engage(a, VOW, self.co, self.tr, cls, {"butterflies": [(i, 2, 3)]},
                             engine, *binary).kind

# write, a routine refusal (audit only), hoard (LEARNING), read (arms the
# trajectory rule), write: records 0-3. After the cut: exfiltrate, which the
# rule must still refuse (audit only), then a write (record 4).
BEFORE = [(0, {"write"}, "c.w"), (1, {"exfiltrate"}, ""), (2, {"hoard", "write"}, "c.h"),
          (3, {"read"}, "c.r"), (4, {"write"}, "c.w2")]
AFTER = [(5, {"exfiltrate", "network_access"}, "c.x"), (6, {"write"}, "c.w3")]

def observable(r):
    return {"report": r.g.report, "outcomes": outcomes(r.L), "drift": analyze(r.L),
            "proven": Adversary("A", r.compressor, b"s")._proven(r.g),
            "trajectory": r.L.trajectory_head(), "head": r.L.head_hash(),
            "audit_head": r.L.audit_head(), "next": r.L.next_record_index()}

@pytest.fixture(scope="module")
def twins(binary):
    plain, packed = Rig(), Rig()
    for step in BEFORE:
        assert plain.run(step, binary) == packed.run(step, binary)
    before = observable(packed)
    cp, archive = compress(packed.L, 3, packed.compressor)   # records 0-2; record 3 stays live
    after = observable(packed)
    kinds = [(plain.run(s, binary), packed.run(s, binary)) for s in AFTER]
    return plain, packed, before, after, cp, archive, kinds

# --- nothing the guard computes changes -----------------------------------------

def test_compression_changes_nothing_observable(twins):
    _, _, before, after, _, _, _ = twins
    assert before == after

def test_the_twins_stay_identical_after_more_engagements(twins):
    plain, packed, _, _, _, _, kinds = twins
    assert all(a == b for a, b in kinds)
    a, b = observable(plain), observable(packed)
    for k in ("report", "outcomes", "drift", "proven", "trajectory", "next"):
        assert a[k] == b[k], k

def test_a_trajectory_rule_armed_before_the_cut_still_holds_after_it(twins):
    plain, packed, _, _, _, _, kinds = twins
    assert kinds[0] == (VerdictKind.LEARNING, VerdictKind.LEARNING)
    assert [a.class_id for a in packed.L.audits if a.class_id.startswith("traj:")] == ["traj:t"]

def test_entries_were_actually_erased(twins):
    plain, packed, _, _, cp, archive, _ = twins
    assert [r.index for r in packed.L.records] == [3, 4]
    assert [r.index for r in archive.records] == [0, 1, 2] and archive.audits
    assert packed.L.verify_integrity()
    assert not set(archive.attestations) & set(packed.L.attestations)
    assert len(packed.L.attestations) < len(plain.L.attestations)

# --- the archive is checkable without trusting the compressor ----------------------

def test_the_archive_verifies_against_its_checkpoint(twins):
    _, packed, _, _, cp, archive, _ = twins
    assert verify_archive(archive, cp, verifiers=packed.L.verifiers) == (True, "ok")

def test_every_erased_entry_has_an_inclusion_proof(twins):
    _, _, _, _, cp, archive, _ = twins
    for kind, entries in (("records", archive.records), ("audits", archive.audits)):
        for e in entries:
            proof = prove_inclusion(archive, cp, kind, e.index)
            assert verify_inclusion(e, proof, cp, kind)
            assert not verify_inclusion(replace(e, class_id="forged"), proof, cp, kind)

@pytest.mark.parametrize("tamper, why", [
    (lambda a: a.records.__setitem__(1, replace(a.records[1], punya_delta=99.0)), ""),
    (lambda a: a.records.pop(), "range"),
    (lambda a: a.audits.pop(0), "range"),
    (lambda a: a.audits.__setitem__(0, replace(a.audits[0], reason="nothing happened")), ""),
    (lambda a: setattr(a, "checkpoint_hash", "0" * 64), "another checkpoint"),
])
def test_a_tampered_archive_is_refused(twins, tamper, why):
    _, packed, _, _, cp, archive, _ = twins
    a = Archive(archive.checkpoint_hash, list(archive.records), list(archive.audits),
                dict(archive.attestations))
    tamper(a)
    ok, reason = verify_archive(a, cp, verifiers=packed.L.verifiers)
    assert not ok and why in reason

def test_a_summary_that_misstates_the_erased_entries_is_caught(twins):
    """A compressor that signs an inflated summary: the signature is fine, the
    archive shows the lie."""
    _, packed, _, _, cp, archive, _ = twins
    s = cp.summary; s["guards"]["G"]["punya"] += 10
    lie = replace(cp, summary_json=compression._canon(s), signature="")
    lie = replace(lie, signature=packed.compressor.sign(lie.payload()).hex())
    a = Archive(lie.hash(), archive.records, archive.audits, archive.attestations)
    ok, reason = verify_archive(a, lie)
    assert not ok and "summary" in reason

def test_an_archived_attestation_must_verify(twins):
    _, packed, _, _, cp, archive, _ = twins
    h = next(iter(archive.attestations))
    a = Archive(archive.checkpoint_hash, archive.records, archive.audits,
                {**archive.attestations, h: replace(archive.attestations[h], signature="00")})
    assert not verify_archive(a, cp, verifiers=packed.L.verifiers)[0]

# --- the live ledger checks its checkpoints ------------------------------------------

def _compressed(binary, cut=3):
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    cp, archive = compress(r.L, cut, r.compressor)
    return r, cp, archive

@pytest.mark.parametrize("damage", ["unsigned", "resigned_by_stranger", "summary", "head", "range"])
def test_a_damaged_checkpoint_breaks_integrity(binary, damage):
    r, cp, _ = _compressed(binary)
    if damage == "unsigned": bad = replace(cp, signature="")
    elif damage == "resigned_by_stranger":
        bad = replace(cp, signer_id="Stranger")
        bad = replace(bad, signature=default_signer("Stranger").sign(bad.payload()).hex())
    elif damage == "summary": bad = replace(cp, summary_json=cp.summary_json.replace('"refused":', '"refused":9'))
    elif damage == "head": bad = replace(cp, record_head="f" * 64)
    else: bad = replace(cp, records_from=1)
    r.L.checkpoints[-1] = bad
    assert not r.L.verify_integrity()

def test_checkpoints_chain_and_offsets_add_up(binary):
    """Two checkpoints: offsets come from the last one, not a sum of indices."""
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    cp1, ar1 = compress(r.L, 2, r.compressor)
    cp2, ar2 = compress(r.L, 4, r.compressor)
    assert (cp2.records_from, cp2.records_through, r.L.next_record_index()) == (2, 3, 4)
    assert cp2.prev_checkpoint == cp1.hash()
    assert verify_archive(ar1, cp1)[0]
    assert verify_archive(ar2, cp2, previous_summary=cp1.summary)[0]
    assert not verify_archive(ar2, cp2)[0]          # the carried state is cumulative
    for step in AFTER: r.run(step, binary)
    assert r.L.verify_integrity() and r.L.records[0].index == 4

def test_compressing_everything_keeps_the_chain_heads(binary):
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    head = r.L.head_hash()
    compress(r.L, 4, r.compressor)
    assert r.L.records == [] and r.L.head_hash() == head
    r.run(AFTER[1], binary)
    assert r.L.records[0].prev_hash == head and r.L.verify_integrity()

@pytest.mark.parametrize("cut, match", [(3, "not past"), (99, "beyond")])
def test_bad_cuts_are_refused(binary, cut, match):
    r, _, _ = _compressed(binary)
    with pytest.raises(CompressionError, match=match): compress(r.L, cut, r.compressor)

def test_a_broken_ledger_is_not_committed_to(binary):
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    r.L.records[1] = replace(r.L.records[1], punya_delta=50.0)
    with pytest.raises(CompressionError, match="does not verify"): compress(r.L, 3, r.compressor)

def test_an_unregistered_signer_cannot_compress(binary):
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    with pytest.raises(CompressionError, match="no registered"):
        compress(r.L, 3, default_signer("Nobody"))

def test_the_persisted_ledger_keeps_its_checkpoints_and_shrinks(binary):
    d = tempfile.mkdtemp(); path = os.path.join(d, "l.json")
    r = Rig(path=path)
    for step in BEFORE: r.run(step, binary)
    before = os.path.getsize(path)
    compress(r.L, 4, r.compressor)
    saved = json.load(open(path))
    assert len(saved["checkpoints"]) == 1 and saved["records"] == []
    assert os.path.getsize(path) < before

def test_a_rule_armed_only_in_the_checkpoint_still_holds(binary):
    """Every record erased: the armed trajectory state now lives only in the
    checkpoint. Losing it would let compression reset the rule."""
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    compress(r.L, 4, r.compressor)
    assert r.L.records == []
    assert r.run(AFTER[0], binary) == VerdictKind.LEARNING
    # refused by the trajectory rule itself, not only by `forbid exfiltrate`
    assert r.L.audits[-1].class_id == "traj:t"


# --- a compressor with a valid key can still sign a bad checkpoint --------------------
# The signature says who vouched; these checks say whether it fits the chain.

def _resign(r, cp, **changes):
    bad = replace(cp, signature="", **changes)
    return replace(bad, signature=r.compressor.sign(bad.payload()).hex())

@pytest.mark.parametrize("changes", [
    {"record_head": "f" * 64},
    {"records_from": 1},
    {"audits_from": 5},
    {"record_bridge": "e" * 64},
    {"prev_checkpoint": "d" * 64},
    {"cut_epoch": 2},
])
def test_a_validly_signed_checkpoint_that_does_not_fit_the_chain_is_refused(binary, changes):
    r, cp, _ = _compressed(binary)
    r.L.checkpoints[-1] = _resign(r, cp, **changes)
    assert not r.L.verify_integrity()

def test_a_second_checkpoint_must_link_to_the_first(binary):
    r = Rig()
    for step in BEFORE: r.run(step, binary)
    compress(r.L, 2, r.compressor); cp2, _ = compress(r.L, 3, r.compressor)
    for changes in ({"prev_checkpoint": "0" * 64}, {"cut_epoch": 2, "records_through": 1}):
        r.L.checkpoints[-1] = _resign(r, cp2, **changes)
        assert not r.L.verify_integrity(), changes
    r.L.checkpoints[-1] = cp2
    assert r.L.verify_integrity()

def test_a_live_audit_cannot_predate_the_cut(binary):
    from audit import AuditEntry
    r, cp, _ = _compressed(binary)
    r.L.record_audit(AuditEntry(index=r.L._audits_offset() + len(r.L.audits),
                                prev_audit_hash=r.L.audit_head(), record_head_ref=r.L.head_hash(),
                                epoch=cp.cut_epoch - 1, guard_id="G", class_id="late", reason="r",
                                co_signer_notes=(), certificate_path="", attestation_hash="",
                                trajectory_attestation="", timestamp=0.0))
    assert not r.L.verify_integrity()

def test_a_live_record_keeps_its_place_after_the_cut(binary):
    r, cp, _ = _compressed(binary)
    assert [x.index for x in r.L.records] == [3]
    r.L.records[0] = replace(r.L.records[0], index=0)   # still links to the checkpoint head
    assert not r.L.verify_integrity()

def test_audits_after_compression_carry_absolute_epochs(binary):
    r, cp, _ = _compressed(binary)
    r.run(AFTER[0], binary)                            # refused: writes an audit
    assert r.L.audits[-1].epoch == r.L.next_record_index() >= cp.cut_epoch

# --- a compressor that commits to something wrong, and signs it --------------------

def _signed_checkpoint(r, recs, auds, base):
    """A checkpoint over exactly these entries, built and signed by hand, the
    way a buggy or dishonest compressor could."""
    cp = replace(base, signature="",
                 records_root=compression.merkle_root([x.hash() for x in recs]),
                 audits_root=compression.merkle_root([x.hash() for x in auds]),
                 record_head=recs[-1].hash(), audit_head=auds[-1].hash(),
                 summary_json=compression._canon(compression.fold(compression.empty_summary(), recs, auds)))
    return replace(cp, signature=r.compressor.sign(cp.payload()).hex())

@pytest.mark.parametrize("field, why", [("records_root", "records root"), ("audits_root", "audits root")])
def test_a_wrong_root_is_caught_even_when_the_chain_is_intact(binary, field, why):
    """Every entry links and the summary is right, but the root the checkpoint
    signed is not theirs: inclusion proofs against it would all fail."""
    r, cp, archive = _compressed(binary)
    bad = replace(cp, signature="", **{field: "0" * 64})
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    a = Archive(bad.hash(), archive.records, archive.audits, archive.attestations)
    ok, reason = verify_archive(a, bad)
    assert not ok and why in reason

@pytest.mark.parametrize("kind", ["records", "audits"])
def test_a_segment_that_never_chained_is_caught(binary, kind):
    """The compressor commits, correctly, to entries that do not link. The
    root and summary match what it was given; only the chain check objects."""
    r, cp, archive = _compressed(binary)
    recs, auds = list(archive.records), list(archive.audits)
    if kind == "records": recs[1] = replace(recs[1], prev_hash="c" * 64)
    else: auds[0] = replace(auds[0], prev_audit_hash="c" * 64)   # off the bridge
    bad = _signed_checkpoint(r, recs, auds, cp)
    ok, reason = verify_archive(Archive(bad.hash(), recs, auds, archive.attestations), bad)
    assert not ok and "does not link" in reason

def test_a_live_audit_keeps_its_index(binary):
    r, cp, _ = _compressed(binary)
    r.run(AFTER[0], binary)                              # a live audit after the cut
    last = r.L.audits[-1]
    r.L.audits[-1] = replace(last, index=last.index + 7) # still links: nothing follows it
    assert not r.L.verify_integrity()

def test_a_cut_that_erases_no_audits_while_later_ones_live(binary):
    """Found by the demo: every audit comes after the cut. The checkpoint's
    audit head must be where the chain stood, not the newest live audit."""
    r = Rig()
    r.run(BEFORE[0], binary); r.run(BEFORE[3], binary)          # records 0, 1; no audits
    r.run(AFTER[0], binary)                                     # refused: audit at epoch 2
    assert [(a.index, a.epoch) for a in r.L.audits] == [(0, 2)]
    cp, archive = compress(r.L, 2, r.compressor)
    assert archive.audits == [] and (cp.audit_bridge, cp.audit_head) == (compression.GENESIS_HASH,) * 2
    assert r.L.verify_integrity() and verify_archive(archive, cp)[0]
    r.run(AFTER[1], binary)
    assert r.L.verify_integrity()


def test_an_empty_ledger_has_nothing_to_compress():
    r = Rig()
    with pytest.raises(CompressionError, match="nothing to erase"): compress(r.L, 0, r.compressor)
