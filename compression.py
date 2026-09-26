
# Layer 7: commit-before-erase.
#
# Old records and audits can be dropped from the live ledger, but only
# losslessly: before anything is erased, a signed Checkpoint commits to every
# erased entry (a Merkle root per chain, plus the hash of the last one), and
# carries forward all the state the guard still reads (merit, proven classes,
# refusal counts, the drift monitor's history, the trajectory automaton
# state). The erased entries and the attestations only they cite go to an
# Archive, which anyone can check against the checkpoint with verify_archive.
#
# Nothing here is lossy or learned: a summary no one can check against the
# originals would be a self-declared claim, which is what this framework
# exists to avoid. Two things this layer does not give you:
#   - The summary is not proven up front. It is committed step by step
#     (trace_root), so anyone holding the archive can convict a wrong summary
#     with a fraud proof that others check without the archive (fraud.py).
#     That rests on one honest archive holder looking. A validity proof
#     (folding / IVC) would not; the `proof` slot is reserved for one.
#   - A checkpoint says nothing about when it was made. anchoring.py stamps
#     it in Bitcoin, which proves it existed no later than a block.
import hashlib, json
from dataclasses import dataclass, field, replace

import merkle

GENESIS_HASH = "0" * 64

def merkle_root(hashes):
    return merkle.root(list(hashes))

class CompressionError(Exception): pass

@dataclass(frozen=True)
class Checkpoint:
    cut_epoch: int                  # erases records < cut_epoch and audits at epoch < cut_epoch
    records_from: int; records_through: int      # through = from - 1 when none erased
    audits_from: int; audits_through: int
    records_root: str; audits_root: str
    record_bridge: str; record_head: str         # prev_hash of the first erased; hash of the last
    audit_bridge: str; audit_head: str
    summary_json: str               # cumulative carried state, canonical JSON
    prev_checkpoint: str; signer_id: str
    trace_root: str = ""            # Merkle root of the fold, one leaf per erased entry
    proof: str = ""                 # reserved for a succinct proof of the erased segment
    signature: str = ""
    def payload(self):
        return "|".join(str(x) for x in (
            "checkpoint/v1", self.cut_epoch, self.records_from, self.records_through,
            self.audits_from, self.audits_through, self.records_root, self.audits_root,
            self.record_bridge, self.record_head, self.audit_bridge, self.audit_head,
            hashlib.sha256(self.summary_json.encode()).hexdigest(),
            self.prev_checkpoint, self.signer_id, self.proof, self.trace_root)).encode()
    def hash(self): return hashlib.sha256(self.payload()).hexdigest()
    @property
    def summary(self): return json.loads(self.summary_json)

@dataclass
class Archive:
    checkpoint_hash: str
    records: list = field(default_factory=list)
    audits: list = field(default_factory=list)
    attestations: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)       # TraceLeaf per erased entry, in fold order

def empty_summary():
    return {"outcomes": "", "guards": {}, "trajectory_state": None}

def _guard(summary, gid):
    return summary["guards"].setdefault(
        gid, {"punya": 0.0, "proven": 0, "refused": 0, "classes": [], "refused_classes": {}})

def is_audit(entry): return hasattr(entry, "prev_audit_hash")

def sort_key(entry):
    # Engagement order: an audit written at epoch k precedes record k.
    return (entry.epoch, 0, entry.index) if is_audit(entry) else (entry.index, 1, entry.index)

def events(records, audits):
    return sorted(list(records) + list(audits), key=sort_key)

def step(state, entry):
    """One erased entry's effect on the carried state. The fold is nothing
    but this, applied in engagement order, so each step can be checked alone."""
    s = json.loads(json.dumps(state))
    if is_audit(entry):
        s["outcomes"] += "1"
        g = _guard(s, entry.guard_id); g["refused"] += 1
        base = entry.class_id.split(":shoshin-")[0]
        g["refused_classes"][base] = g["refused_classes"].get(base, 0) + 1
    else:
        s["outcomes"] += "1" if entry.verdict_kind == "LEARNING" else "0"
        g = _guard(s, entry.guard_id)
        g["punya"] += entry.punya_delta; g["proven"] += 1
        if entry.class_id and entry.verdict_kind in ("LAWFUL", "LEARNING") \
                and entry.class_id not in g["classes"]:
            g["classes"] = sorted(g["classes"] + [entry.class_id])
        s["trajectory_state"] = list(entry.trajectory_state)
    return s

def fold(summary, records, audits):
    """Carry state forward over an erased segment. Everything the guard,
    adversary and drift monitor read from erased entries lands here."""
    s = json.loads(json.dumps(summary))
    for e in events(records, audits): s = step(s, e)
    return s

def _canon(s): return json.dumps(s, sort_keys=True, separators=(",", ":"))

def state_digest(state): return hashlib.sha256(_canon(state).encode()).hexdigest()

@dataclass(frozen=True)
class TraceLeaf:
    """Step k of the fold: which entry it consumed (its chain and position),
    how many of each chain were consumed so far, and the state after it."""
    k: int; kind: str; pos: int; entry_hash: str
    n_records: int; n_audits: int; state: str       # state_digest after the step
    def digest(self):
        return hashlib.sha256(f"leaf/v1|{self.k}|{self.kind}|{self.pos}|{self.entry_hash}|"
                              f"{self.n_records}|{self.n_audits}|{self.state}".encode()).hexdigest()

def trace(prev_summary, records, audits):
    """The honest fold, one leaf per step. Returns (leaves, states)."""
    leaves, states, s = [], [], prev_summary
    nr = na = 0
    for k, e in enumerate(events(records, audits)):
        s = step(s, e)
        if is_audit(e): na += 1; kind, pos = "audits", na - 1
        else: nr += 1; kind, pos = "records", nr - 1
        leaves.append(TraceLeaf(k, kind, pos, e.hash(), nr, na, state_digest(s)))
        states.append(s)
    return leaves, states

def trace_root(leaves): return merkle_root([l.digest() for l in leaves])

def _cited(records, audits):
    out = set()
    for r in records: out.update(x for x in (r.attestation_hash, r.trajectory_attestation) if x)
    for a in audits: out.update(x for x in (a.attestation_hash, a.trajectory_attestation) if x)
    return out

def compress(ledger, cut_epoch, signer):
    """Erase every record with index < cut_epoch and every audit written at an
    epoch < cut_epoch, after committing to them. Returns (checkpoint, archive).
    A ledger that does not verify is refused: committing to it would launder
    whatever is wrong with it."""
    if not ledger.verify_integrity():
        raise CompressionError("ledger does not verify; refusing to commit to it")
    if signer.id not in ledger.verifiers:
        raise CompressionError(f"signer {signer.id!r} has no registered verifier")
    last = ledger.checkpoints[-1] if ledger.checkpoints else None
    if cut_epoch <= (last.cut_epoch if last else 0):
        raise CompressionError(f"cut {cut_epoch} is not past the last checkpoint "
                               f"({last.cut_epoch if last else 0}): nothing to erase")
    if cut_epoch > ledger.next_record_index():
        raise CompressionError(f"cut {cut_epoch} is beyond the ledger ({ledger.next_record_index()})")
    recs = [r for r in ledger.records if r.index < cut_epoch]
    auds = [a for a in ledger.audits if a.epoch < cut_epoch]
    if auds != ledger.audits[:len(auds)]:
        raise CompressionError("audits below the cut are not a prefix of the audit chain")
    r_from, a_from = ledger._records_offset(), ledger._audits_offset()
    # Where each chain stood when this segment began: an empty segment starts
    # and ends there, whatever live entries come after the cut.
    r_start = last.record_head if last else ledger.genesis_hash
    a_start = last.audit_head if last else GENESIS_HASH
    leaves, states = trace(last.summary if last else empty_summary(), recs, auds)
    summary = states[-1] if states else (last.summary if last else empty_summary())
    cp = Checkpoint(
        cut_epoch=cut_epoch,
        records_from=r_from, records_through=r_from + len(recs) - 1,
        audits_from=a_from, audits_through=a_from + len(auds) - 1,
        records_root=merkle_root([r.hash() for r in recs]),
        audits_root=merkle_root([a.hash() for a in auds]),
        record_bridge=recs[0].prev_hash if recs else r_start,
        record_head=recs[-1].hash() if recs else r_start,
        audit_bridge=auds[0].prev_audit_hash if auds else a_start,
        audit_head=auds[-1].hash() if auds else a_start,
        summary_json=_canon(summary),
        prev_checkpoint=last.hash() if last else GENESIS_HASH,
        signer_id=signer.id, trace_root=trace_root(leaves))
    cp = replace(cp, signature=signer.sign(cp.payload()).hex())
    keep_r, keep_a = ledger.records[len(recs):], ledger.audits[len(auds):]
    erased_att = _cited(recs, auds) - _cited(keep_r, keep_a)
    archive = Archive(cp.hash(), list(recs), list(auds),
                      {h: ledger.attestations[h] for h in erased_att if h in ledger.attestations},
                      list(leaves))
    ledger.checkpoints.append(cp)
    ledger.records[:] = keep_r; ledger.audits[:] = keep_a
    for h in erased_att: ledger.attestations.pop(h, None)
    ledger._persist()
    if not ledger.verify_integrity():            # cannot happen; if it does, say so loudly
        raise CompressionError("ledger failed to verify after compression")
    return cp, archive

def verify_archive(archive, checkpoint, previous_summary=None, verifiers=None):
    """Check an archive against its checkpoint without trusting either party:
    roots, chain links, heads and the carried summary are all recomputed from
    the archived entries. With verifiers, archived attestation signatures are
    checked too. previous_summary is the summary of the checkpoint before this
    one (None for the first)."""
    if archive.checkpoint_hash != checkpoint.hash(): return False, "archive is for another checkpoint"
    recs, auds = archive.records, archive.audits
    if [r.index for r in recs] != list(range(checkpoint.records_from, checkpoint.records_through + 1)):
        return False, "record indices do not cover the checkpoint's range"
    if [a.index for a in auds] != list(range(checkpoint.audits_from, checkpoint.audits_through + 1)):
        return False, "audit indices do not cover the checkpoint's range"
    if merkle_root([r.hash() for r in recs]) != checkpoint.records_root: return False, "records root mismatch"
    if merkle_root([a.hash() for a in auds]) != checkpoint.audits_root: return False, "audits root mismatch"
    prev = checkpoint.record_bridge
    for r in recs:
        if r.prev_hash != prev: return False, f"record {r.index} does not link"
        prev = r.hash()
    if prev != checkpoint.record_head: return False, "record head mismatch"
    prev = checkpoint.audit_bridge
    for a in auds:
        if a.prev_audit_hash != prev: return False, f"audit {a.index} does not link"
        prev = a.hash()
    if prev != checkpoint.audit_head: return False, "audit head mismatch"
    if any(r.index >= checkpoint.cut_epoch for r in recs) or any(a.epoch >= checkpoint.cut_epoch for a in auds):
        return False, "an archived entry is past the cut"
    leaves, states = trace(previous_summary or empty_summary(), recs, auds)
    final = states[-1] if states else (previous_summary or empty_summary())
    if _canon(final) != checkpoint.summary_json:
        return False, "carried summary does not match the archived entries"
    if trace_root(leaves) != checkpoint.trace_root:
        return False, "trace root does not match the archived entries"
    if verifiers is not None:
        for h, a in archive.attestations.items():
            v = verifiers.get(a.signer_id)
            if h != a.attestation_hash() or v is None or not a.signature \
                    or not v.verify(a.payload(), bytes.fromhex(a.signature)):
                return False, f"archived attestation {h[:12]} does not verify"
    return True, "ok"

def prove_inclusion(archive, checkpoint, kind, index):
    """Merkle path showing one erased entry is committed by the checkpoint."""
    entries = archive.records if kind == "records" else archive.audits
    start = checkpoint.records_from if kind == "records" else checkpoint.audits_from
    return merkle.path([e.hash() for e in entries], index - start)

def verify_inclusion(entry, proof, checkpoint, kind):
    root = checkpoint.records_root if kind == "records" else checkpoint.audits_root
    return merkle.verify(entry.hash(), proof, root)
