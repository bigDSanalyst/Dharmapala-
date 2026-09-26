"""Fraud proofs: a wrong checkpoint can be convicted without its archive,
and a right one cannot be.

Every lie below is built the way a dishonest compressor with a valid key
would: doctored, re-signed, and structurally sound, so the live ledger's own
checks pass it. An honest archive holder then finds a proof, and the proof
convicts with nothing but the checkpoint and the summary before it."""
import hashlib, json, math, os, tempfile
from dataclasses import replace

import pytest

import tests.support  # noqa: F401
import compression
from compression import Archive, TraceLeaf, compress, empty_summary, events, state_digest, step
from doctor import observe as doctor_observe
from fraud import FraudProof, find_fraud, verify_fraud
from tests.test_compression import AFTER, BEFORE, Rig, binary  # noqa: F401  (fixture)

def honest(binary, cut=3, twice=False):
    r = Rig()
    for s in BEFORE: r.run(s, binary)
    if twice:
        cp0, ar0 = compress(r.L, 2, r.compressor)
    cp, archive = compress(r.L, cut, r.compressor)
    return r, cp, archive

def doctored(r, cp, archive, prev=None, tamper=None, entries=None, relabel=None):
    """Re-run the fold with a lie in it, commit to the lie, sign it."""
    prev = prev if prev is not None else empty_summary()
    evs = entries if entries is not None else events(archive.records, archive.audits)
    leaves, s, nr, na = [], prev, 0, 0
    for k, e in enumerate(evs):
        s = step(s, e)
        if tamper: s = tamper(k, s)
        if compression.is_audit(e): na += 1; kind, pos = "audits", na - 1
        else: nr += 1; kind, pos = "records", nr - 1
        leaf = TraceLeaf(k, kind, pos, e.hash(), nr, na, state_digest(s))
        leaves.append(relabel(k, leaf) if relabel else leaf)
    bad = replace(cp, signature="", trace_root=compression.trace_root(leaves),
                  summary_json=compression._canon(s))
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    return bad, Archive(bad.hash(), archive.records, archive.audits, archive.attestations, leaves)

def convict(r, bad, bad_archive, expect_kind):
    r.L.checkpoints[-1] = bad
    assert r.L.verify_integrity(), "the lie must pass the live ledger's own checks"
    proof, why = find_fraud(bad_archive, bad, r.L.prev_summary(len(r.L.checkpoints) - 1))
    assert proof is not None, why
    assert proof.kind == expect_kind, (proof.kind, why)
    assert verify_fraud(proof, bad, r.L.prev_summary(len(r.L.checkpoints) - 1))[0]
    r.L.dispute(len(r.L.checkpoints) - 1, proof)
    assert not r.L.verify_integrity()
    _, findings = doctor_observe(r.L)
    assert "checkpoint_convicted" in {f.name for f in findings if f.level == "BLOCK"}
    return proof

# --- every way to lie has a proof ------------------------------------------------------

def test_a_summary_that_is_not_where_the_trace_ends(binary):
    r, cp, archive = honest(binary)
    s = cp.summary; s["guards"]["G"]["punya"] += 10
    bad = replace(cp, signature="", summary_json=compression._canon(s))
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    convict(r, bad, Archive(bad.hash(), archive.records, archive.audits,
                            archive.attestations, archive.trace), "final")

@pytest.mark.parametrize("at", [0, 1, "last"])
def test_merit_inflated_at_one_step_and_carried_through(binary, at):
    r, cp, archive = honest(binary)
    n = len(archive.trace); j = n - 1 if at == "last" else at
    def tamper(k, s):
        if k == j: s["guards"].setdefault("G", {"punya": 0.0, "proven": 0, "refused": 0,
                                                "classes": [], "refused_classes": {}})["punya"] += 10
        return s
    proof = convict(r, *doctored(r, cp, archive, tamper=tamper), "step")
    assert proof.k == j

def test_a_refusal_quietly_dropped_from_the_outcomes(binary):
    r, cp, archive = honest(binary)
    def tamper(k, s):
        if k == 1: s["outcomes"] = s["outcomes"][:-1] + "0"
        return s
    convict(r, *doctored(r, cp, archive, tamper=tamper), "step")

def test_an_erased_entry_left_out_of_the_fold(binary):
    """A shorter trace leaves no step to point at: the replay convicts it."""
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    drop = next(i for i, e in enumerate(evs) if compression.is_audit(e))   # the routine refusal
    convict(r, *doctored(r, cp, archive, entries=evs[:drop] + evs[drop + 1:]), "replay")

def test_an_entry_folded_twice_in_place_of_another(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    evs[2] = evs[1] if not compression.is_audit(evs[1]) else evs[0]
    convict(r, *doctored(r, cp, archive, entries=evs), "bind")

def test_an_entry_folded_twice_keeping_its_numbering(binary):
    """The repeat keeps its first position: the chain position repeats."""
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    j = next(i for i in range(1, len(evs)) if not compression.is_audit(evs[i]) and not compression.is_audit(evs[i - 1]))
    evs[j] = evs[j - 1]
    first = {}
    def relabel(k, leaf):
        if leaf.entry_hash in first: return replace(leaf, pos=first[leaf.entry_hash])
        first[leaf.entry_hash] = leaf.pos; return leaf
    convict(r, *doctored(r, cp, archive, entries=evs, relabel=relabel), "order")

def test_entries_folded_out_of_engagement_order(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    i = next(i for i in range(len(evs) - 1) if compression.is_audit(evs[i]) != compression.is_audit(evs[i + 1]))
    evs[i], evs[i + 1] = evs[i + 1], evs[i]
    convict(r, *doctored(r, cp, archive, entries=evs), "order")

def test_a_forged_entry_folded_in_place_of_the_real_one(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    j = next(i for i, e in enumerate(evs) if not compression.is_audit(e) and e.verdict_kind == "LEARNING")
    evs[j] = replace(evs[j], verdict_kind="LAWFUL", punya_delta=2.0)      # the refusal, laundered
    convict(r, *doctored(r, cp, archive, entries=evs), "bind")

def test_a_lie_in_the_second_checkpoint_is_judged_against_the_first(binary):
    r, cp, archive = honest(binary, cut=4, twice=True)
    prev = r.L.checkpoints[-2].summary
    def tamper(k, s):
        if k == 0: s["guards"]["G"]["refused"] -= 1
        return s
    convict(r, *doctored(r, cp, archive, prev=prev, tamper=tamper), "step")

# --- an honest compressor cannot be framed ---------------------------------------------

def test_an_honest_checkpoint_has_no_fraud(binary):
    r, cp, archive = honest(binary)
    assert find_fraud(archive, cp) == (None, "no fraud")
    r2, cp2, ar2 = honest(binary, cut=4, twice=True)
    assert find_fraud(ar2, cp2, r2.L.prev_summary(1)) == (None, "no fraud")

def _leaf_path(archive, k):
    import merkle
    return merkle.path([l.digest() for l in archive.trace], k)

@pytest.mark.parametrize("forge", ["fake_state", "fake_leaf", "wrong_position", "fake_chain", "final", "order"])
def test_forged_proofs_against_an_honest_checkpoint_are_refused(binary, forge):
    r, cp, archive = honest(binary)
    t = archive.trace; evs = events(archive.records, archive.audits)
    k = 1
    common = dict(k=k, leaf=t[k], leaf_path=_leaf_path(archive, k), prev_leaf=t[0], prev_path=_leaf_path(archive, 0))
    if forge == "fake_state":      # claim step 1 is wrong by starting it from a made-up state
        p = FraudProof("step", prev_state={**empty_summary(), "outcomes": "111"}, entry=evs[k], **common)
    elif forge == "fake_leaf":     # a leaf the checkpoint never committed to
        p = FraudProof("step", prev_state=None, entry=evs[k],
                       **{**common, "leaf": replace(t[k], state="0" * 64)})
    elif forge == "wrong_position":  # a real leaf, presented as another step
        p = FraudProof("step", prev_state=None, entry=evs[k], **{**common, "k": 2})
    elif forge == "fake_chain":    # claim the committed entry is something else
        p = FraudProof("bind", chain_hash="ab" * 32, chain_path=(), **common)
    elif forge == "final":
        last = len(t) - 1
        p = FraudProof("final", k=last, leaf=t[last], leaf_path=_leaf_path(archive, last),
                       prev_leaf=t[last - 1], prev_path=_leaf_path(archive, last - 1))
    else:
        p = FraudProof("order", entry=evs[k], prev_entry=evs[k - 1], **common)
    assert not verify_fraud(p, cp)[0]
    with pytest.raises(ValueError, match="refused"):
        r.L.dispute(0, p)
    assert r.L.verify_integrity() and not r.L.disputes

def test_proofs_are_small(binary):
    r, cp, archive = honest(binary)
    bad, bad_archive = doctored(r, cp, archive, tamper=lambda k, s: s if k != 2 else {**s, "outcomes": s["outcomes"] + "0"})
    proof, _ = find_fraud(bad_archive, bad)
    n = len(archive.trace)
    assert len(proof.leaf_path) <= math.ceil(math.log2(n)) + 1 >= len(proof.prev_path)
    assert proof.prev_state is not None and proof.entry is not None   # one state, one entry

# --- when there is nothing to point into ------------------------------------------------

def _inflated(r, cp):
    s = cp.summary; s["guards"]["G"]["punya"] += 10
    bad = replace(cp, signature="", summary_json=compression._canon(s))
    return replace(bad, signature=r.compressor.sign(bad.payload()).hex())

def test_a_withheld_trace_is_convicted_by_replay(binary):
    r, cp, archive = honest(binary)
    bad = _inflated(r, cp)
    convict(r, bad, Archive(bad.hash(), archive.records, archive.audits, archive.attestations, []), "replay")

def test_withheld_entries_are_named_not_passed(binary):
    r, cp, archive = honest(binary)
    bad = _inflated(r, cp)
    proof, why = find_fraud(Archive(bad.hash(), [], [], {}, []), bad)
    assert proof is None and "unavailable" in why and why != "no fraud"

@pytest.mark.parametrize("bogus", ["missing", "altered", "reordered"])
def test_bogus_entries_cannot_convict_an_honest_checkpoint_by_replay(binary, bogus):
    r, cp, archive = honest(binary)
    recs = list(archive.records)
    if bogus == "missing": recs.pop()
    elif bogus == "altered": recs[0] = replace(recs[0], punya_delta=77.0)
    else: recs[0], recs[1] = recs[1], recs[0]
    p = FraudProof("replay", k=-1, leaf=None, leaf_path=(), records=tuple(recs), audits=tuple(archive.audits))
    assert not verify_fraud(p, cp)[0]
    with pytest.raises(ValueError, match="refused"): r.L.dispute(0, p)
    honest_replay = FraudProof("replay", k=-1, leaf=None, leaf_path=(),
                               records=tuple(archive.records), audits=tuple(archive.audits))
    assert verify_fraud(honest_replay, cp) == (False, "the committed entries replay to exactly this checkpoint")

def test_verify_archive_checks_the_trace_root(binary):
    r, cp, archive = honest(binary)
    bad = replace(cp, signature="", trace_root="0" * 64)
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    ok, why = compression.verify_archive(Archive(bad.hash(), archive.records, archive.audits,
                                                 archive.attestations, archive.trace), bad)
    assert not ok and "trace root" in why

# --- framing: every way to point a proof at an honest checkpoint ---------------------------
# Found by mutation testing: each check below was untested until these existed.

def _proof(archive, kind, k, **kw):
    t = archive.trace
    base = dict(k=k, leaf=t[k], leaf_path=_leaf_path(archive, k))
    if k: base.update(prev_leaf=t[k - 1], prev_path=_leaf_path(archive, k - 1))
    base.update(kw)
    return FraudProof(kind, **base)

def _refused(r, cp, proof):
    assert not verify_fraud(proof, cp)[0]
    with pytest.raises(ValueError, match="refused"): r.L.dispute(0, proof)
    assert r.L.verify_integrity()

def test_final_cannot_be_pointed_at_an_intermediate_step(binary):
    """An intermediate state differs from the summary by nature."""
    r, cp, archive = honest(binary)
    _refused(r, cp, _proof(archive, "final", 1))

def test_order_cannot_use_entries_that_are_not_the_leaves(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    _refused(r, cp, _proof(archive, "order", 2, entry=evs[1], prev_entry=evs[2]))   # swapped

def test_step_cannot_use_a_forged_entry(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    k = next(i for i, e in enumerate(evs) if i and not compression.is_audit(e))
    from compression import trace
    _, states = trace(empty_summary(), archive.records, archive.audits)
    forged = replace(evs[k], punya_delta=50.0)
    _refused(r, cp, _proof(archive, "step", k, entry=forged, prev_state=states[k - 1]))

def test_step_cannot_start_from_a_leaf_outside_the_trace(binary):
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    fake_prev_state = {**empty_summary(), "outcomes": "11111"}
    fake_prev = replace(archive.trace[1], state=state_digest(fake_prev_state))
    _refused(r, cp, _proof(archive, "step", 2, entry=evs[2], prev_leaf=fake_prev, prev_state=fake_prev_state))

# --- each conviction rule fires on its own ---------------------------------------------------

def _first(r, bad, bad_archive):
    r.L.checkpoints[-1] = bad
    proof, why = find_fraud(bad_archive, bad)
    assert proof is not None, why
    ok, reason = verify_fraud(proof, bad)
    assert ok, reason
    return proof, reason

def test_garbage_k_fields_do_not_shield_a_lie(binary):
    r, cp, archive = honest(binary)
    bad, ba = doctored(r, cp, archive, relabel=lambda k, leaf: replace(leaf, k=99),
                       tamper=lambda k, s: s if k != 1 else {**s, "outcomes": s["outcomes"] + "1"})
    proof, _ = _first(r, bad, ba)
    assert (proof.kind, proof.k) == ("step", 1)

def test_a_position_outside_the_chain(binary):
    r, cp, archive = honest(binary)
    bad, ba = doctored(r, cp, archive, relabel=lambda k, leaf: replace(leaf, pos=99) if k == 2 else leaf)
    proof, reason = _first(r, bad, ba)
    assert (proof.kind, proof.k) == ("bind", 2) and "outside" in reason

def test_counts_that_jump_are_caught_at_the_jump(binary):
    r, cp, archive = honest(binary)
    def relabel(k, leaf):
        return replace(leaf, n_records=leaf.n_records + 1) if k == 1 else leaf
    proof, reason = _first(r, *doctored(r, cp, archive, relabel=relabel))
    assert (proof.kind, proof.k) == ("order", 1) and "counts" in reason

def test_a_skipped_position_is_caught_where_it_is_skipped(binary):
    """Skip a record but keep n leaves by repeating the last one at the end.
    The skip is the first wrong step, before the repeat."""
    r, cp, archive = honest(binary)
    evs = events(archive.records, archive.audits)
    i = next(i for i, e in enumerate(evs) if i and not compression.is_audit(e))
    real_pos = {e.hash(): p for p, e in enumerate(archive.records)}
    entries = evs[:i] + evs[i + 1:] + [evs[-1]]
    relabel = lambda k, leaf: replace(leaf, pos=real_pos[leaf.entry_hash]) \
        if leaf.kind == "records" and k < len(entries) - 1 else leaf
    proof, reason = _first(r, *doctored(r, cp, archive, entries=entries, relabel=relabel))
    assert (proof.kind, proof.k) == ("order", i) and "position" in reason

def test_final_counts_short_of_the_ranges(binary):
    """A crafted final proof: the last leaf ends at the summary but claims to
    have consumed fewer entries than the checkpoint erased."""
    r, cp, archive = honest(binary)
    n = len(archive.trace)
    bad, ba = doctored(r, cp, archive, relabel=lambda k, leaf: replace(leaf, n_records=0) if k == n - 1 else leaf)
    last = n - 1
    p = FraudProof("final", k=last, leaf=ba.trace[last], leaf_path=_leaf_path(ba, last),
                   prev_leaf=ba.trace[last - 1], prev_path=_leaf_path(ba, last - 1))
    ok, reason = verify_fraud(p, bad)
    assert ok and "consume" in reason

def test_replay_convicts_a_bogus_trace_root_even_with_a_true_summary(binary):
    r, cp, archive = honest(binary)
    bad = replace(cp, signature="", trace_root="1" * 64)
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    p = FraudProof("replay", k=-1, leaf=None, leaf_path=(), records=tuple(archive.records), audits=tuple(archive.audits))
    ok, reason = verify_fraud(p, bad)
    assert ok and "committed trace" in reason

def test_replay_convicts_committed_entries_outside_the_declared_range(binary):
    r, cp, archive = honest(binary)
    bad = replace(cp, signature="", records_from=cp.records_from + 1)
    bad = replace(bad, signature=r.compressor.sign(bad.payload()).hex())
    p = FraudProof("replay", k=-1, leaf=None, leaf_path=(), records=tuple(archive.records), audits=tuple(archive.audits))
    ok, reason = verify_fraud(p, bad)
    assert ok and "ranges" in reason

def test_the_trace_root_is_signed(binary):
    r, cp, archive = honest(binary)
    r.L.checkpoints[-1] = replace(cp, trace_root="2" * 64)          # not re-signed
    assert not r.L.verify_integrity()
