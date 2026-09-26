
# Fraud proofs: convicting a wrong checkpoint without its archive.
#
# A checkpoint's summary is signed, and a signature only says who vouched.
# Each checkpoint also commits to its fold step by step (trace_root, one leaf
# per erased entry). If any step is wrong, whoever holds the archive can
# point at it: the proof carries O(log n) hashes, the entries touching that
# step, and one carried state. The verifier needs only the checkpoint and
# the summary of the checkpoint before it, both of which the live ledger keeps.
#
# Four ways a checkpoint can lie, one proof kind each:
#   step   leaf k's state is not step(state of leaf k-1, the entry it names)
#   bind   leaf k names an entry that is not the one committed at its position
#   order  leaf k skips, repeats or reorders entries
#   final  the last leaf's state or counts are not the signed summary
# If every step is bound, ordered and correct, and the last one ends at the
# signed summary, the summary is right. So a wrong summary always has a proof.
#
# A compressor can dodge the succinct proofs by committing to a malformed
# trace (wrong length, or leaves it never publishes). The fifth kind covers
# that, at O(n) cost:
#   replay the erased entries themselves. They must first prove to be exactly
#          what the checkpoint committed (every position, both roots), so
#          bogus data can never convict an honest checkpoint; then any
#          mismatch in links, heads, trace or summary is the checkpoint's own.
# Only a compressor who withholds the erased entries entirely escapes; find_fraud
# says so rather than returning "no fraud".
from dataclasses import dataclass
from typing import Optional

import merkle
from compression import (_canon, empty_summary, is_audit, sort_key, state_digest, step,
                         trace, trace_root)

@dataclass(frozen=True)
class FraudProof:
    kind: str; k: int                                 # "step" | "bind" | "order" | "final"
    leaf: object; leaf_path: tuple                    # TraceLeaf k and its path in trace_root
    prev_leaf: object = None; prev_path: tuple = ()   # TraceLeaf k-1, when k > 0
    prev_state: Optional[dict] = None                 # full state after k-1 (step)
    entry: object = None                              # the entry leaf k names (step, order)
    prev_entry: object = None                         # the entry leaf k-1 names (order)
    chain_hash: str = ""; chain_path: tuple = ()      # what is really at leaf.pos (bind)
    records: tuple = (); audits: tuple = ()           # the erased entries (replay)

def _n(cp):
    return (cp.records_through - cp.records_from + 1) + (cp.audits_through - cp.audits_from + 1)

def _size(cp, kind):
    return (cp.records_through - cp.records_from + 1) if kind == "records" \
        else (cp.audits_through - cp.audits_from + 1)

def _in_trace(leaf, path, cp, k):
    # The path's shape fixes the position; the leaf's own `k` field is not
    # consulted. A compressor that commits garbage there must not thereby
    # make every proof against it inadmissible.
    return leaf is not None and merkle.verify_at(leaf.digest(), path, cp.trace_root, _n(cp), k)

def _verify_replay(proof, cp, base):
    recs, auds = list(proof.records), list(proof.audits)
    # Authenticate first: these must be exactly the entries the checkpoint committed to.
    if merkle.root([r.hash() for r in recs]) != cp.records_root or \
            merkle.root([a.hash() for a in auds]) != cp.audits_root:
        return False, "entries are not the ones the checkpoint committed"
    # Now anything that does not fit is the checkpoint's fault.
    if [r.index for r in recs] != list(range(cp.records_from, cp.records_through + 1)) or \
            [a.index for a in auds] != list(range(cp.audits_from, cp.audits_through + 1)):
        return True, "committed entries do not cover the checkpoint's ranges"
    prev = cp.record_bridge
    for r in recs:
        if r.prev_hash != prev: return True, f"committed record {r.index} does not link"
        prev = r.hash()
    if prev != cp.record_head: return True, "committed records do not end at the checkpoint's head"
    prev = cp.audit_bridge
    for a in auds:
        if a.prev_audit_hash != prev: return True, f"committed audit {a.index} does not link"
        prev = a.hash()
    if prev != cp.audit_head: return True, "committed audits do not end at the checkpoint's head"
    if any(r.index >= cp.cut_epoch for r in recs) or any(a.epoch >= cp.cut_epoch for a in auds):
        return True, "a committed entry is past the cut"
    leaves, states = trace(base, recs, auds)
    if _canon(states[-1] if states else base) != cp.summary_json:
        return True, "the committed entries do not fold to the signed summary"
    if trace_root(leaves) != cp.trace_root:
        return True, "the committed entries do not fold to the committed trace"
    return False, "the committed entries replay to exactly this checkpoint"

def verify_fraud(proof, checkpoint, prev_summary=None):
    """True when the proof shows the checkpoint is wrong. Needs no archive.
    prev_summary is the summary of the checkpoint before (None for the first)."""
    cp, k, leaf = checkpoint, proof.k, proof.leaf
    base = prev_summary if prev_summary is not None else empty_summary()
    if proof.kind == "replay": return _verify_replay(proof, cp, base)
    if not _in_trace(leaf, proof.leaf_path, cp, k):
        return False, "leaf is not step k of this checkpoint's trace"
    if k > 0 and not _in_trace(proof.prev_leaf, proof.prev_path, cp, k - 1):
        return False, "previous leaf is not step k-1 of this checkpoint's trace"
    prev_counts = (proof.prev_leaf.n_records, proof.prev_leaf.n_audits) if k else (0, 0)

    if proof.kind == "final":
        if k != _n(cp) - 1: return False, "not the last step"
        if leaf.state != state_digest(cp.summary): return True, "the trace does not end at the signed summary"
        if (leaf.n_records, leaf.n_audits) != (_size(cp, "records"), _size(cp, "audits")):
            return True, "the trace does not consume every erased entry"
        return False, "the last step ends at the signed summary"

    if proof.kind == "bind":
        size = _size(cp, leaf.kind) if leaf.kind in ("records", "audits") else 0
        if not 0 <= leaf.pos < size: return True, f"leaf names position {leaf.pos} outside its chain"
        root = cp.records_root if leaf.kind == "records" else cp.audits_root
        if not merkle.verify_at(proof.chain_hash, proof.chain_path, root, size, leaf.pos):
            return False, "chain path does not prove what is at that position"
        if proof.chain_hash != leaf.entry_hash:
            return True, "leaf names an entry that is not the one committed at its position"
        return False, "leaf names the committed entry"

    if proof.kind == "order":
        nr, na = prev_counts
        expect = (nr + 1, na) if leaf.kind == "records" else (nr, na + 1)
        if leaf.kind not in ("records", "audits") or (leaf.n_records, leaf.n_audits) != expect:
            return True, "counts do not advance by exactly one entry"
        if leaf.pos != (expect[0] if leaf.kind == "records" else expect[1]) - 1:
            return True, "leaf skips or repeats a position in its chain"
        if k > 0:
            e, pe = proof.entry, proof.prev_entry
            if e is None or pe is None or e.hash() != leaf.entry_hash or pe.hash() != proof.prev_leaf.entry_hash:
                return False, "entries do not match the leaves"
            if sort_key(pe) >= sort_key(e): return True, "entries are out of engagement order"
        return False, "step k is in order"

    if proof.kind == "step":
        e = proof.entry
        if e is None or e.hash() != leaf.entry_hash: return False, "entry does not match the leaf"
        if (leaf.kind == "audits") != is_audit(e): return False, "entry is not of the leaf's kind"
        if k == 0: prev = base
        else:
            prev = proof.prev_state
            if prev is None or state_digest(prev) != proof.prev_leaf.state:
                return False, "previous state does not match the previous leaf"
        if state_digest(step(prev, e)) != leaf.state:
            return True, "the state after step k is not what the entry makes it"
        return False, "step k is correct"

    return False, f"unknown proof kind {proof.kind!r}"

def find_fraud(archive, checkpoint, prev_summary=None):
    """What an honest archive holder runs. Returns (proof or None, reason).
    None with "no fraud" means the checkpoint is right; None with any other
    reason means no succinct proof can be made (see the module docstring)."""
    cp = checkpoint
    base = prev_summary if prev_summary is not None else empty_summary()
    published = list(archive.trace)
    if len(published) != _n(cp) or trace_root(published) != cp.trace_root:
        replay = FraudProof("replay", k=-1, leaf=None, leaf_path=(),
                            records=tuple(archive.records), audits=tuple(archive.audits))
        ok, why = verify_fraud(replay, cp, prev_summary)
        if ok: return replay, "replay: " + why
        return None, "trace unavailable and the erased entries do not convict: " + why
    digests = [l.digest() for l in published]
    path = lambda k: merkle.path(digests, k)
    chains = {"records": [r.hash() for r in archive.records], "audits": [a.hash() for a in archive.audits]}
    entries = {r.hash(): r for r in archive.records}; entries.update({a.hash(): a for a in archive.audits})
    if merkle.root(chains["records"]) != cp.records_root or merkle.root(chains["audits"]) != cp.audits_root:
        return None, "archive does not match the checkpoint's roots"
    state = base
    for k, leaf in enumerate(published):
        prev = published[k - 1] if k else None
        common = dict(k=k, leaf=leaf, leaf_path=path(k),
                      prev_leaf=prev, prev_path=path(k - 1) if k else ())
        chain = chains.get(leaf.kind, [])
        if not 0 <= leaf.pos < len(chain) or chain[leaf.pos] != leaf.entry_hash:
            ok_pos = 0 <= leaf.pos < len(chain)
            return FraudProof("bind", chain_hash=chain[leaf.pos] if ok_pos else "",
                              chain_path=merkle.path(chain, leaf.pos) if ok_pos else (),
                              **common), "bind"
        e = entries[leaf.entry_hash]
        order = FraudProof("order", entry=e, prev_entry=entries[prev.entry_hash] if prev else None, **common)
        if verify_fraud(order, cp, prev_summary)[0]: return order, "order"
        stepped = step(state, e)
        if state_digest(stepped) != leaf.state:
            return FraudProof("step", prev_state=state if k else None, entry=e, **common), "step"
        state = stepped
    if published:
        last = len(published) - 1
        final = FraudProof("final", k=last, leaf=published[last], leaf_path=path(last),
                           prev_leaf=published[last - 1] if last else None,
                           prev_path=path(last - 1) if last else ())
        if verify_fraud(final, cp, prev_summary)[0]: return final, "final"
    elif _canon(base) != cp.summary_json:
        return None, "empty segment with a changed summary: nothing to point into; replay shows it"
    return None, "no fraud"
