
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
#   - The summary is signed, not proven. Until someone runs verify_archive,
#     trusting it means trusting the compressor's key. (A recursive proof
#     - folding / IVC - that every erased entry verified would remove that
#     trust; the `proof` slot is where one would go.)
#   - A checkpoint says nothing about when it was made; its hash() is what to
#     anchor with an external timestamp.
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
    proof: str = ""                 # reserved for a succinct proof of the erased segment
    signature: str = ""
    def payload(self):
        return "|".join(str(x) for x in (
            "checkpoint/v1", self.cut_epoch, self.records_from, self.records_through,
            self.audits_from, self.audits_through, self.records_root, self.audits_root,
            self.record_bridge, self.record_head, self.audit_bridge, self.audit_head,
            hashlib.sha256(self.summary_json.encode()).hexdigest(),
            self.prev_checkpoint, self.signer_id, self.proof)).encode()
    def hash(self): return hashlib.sha256(self.payload()).hexdigest()
    @property
    def summary(self): return json.loads(self.summary_json)

@dataclass
class Archive:
    checkpoint_hash: str
    records: list = field(default_factory=list)
    audits: list = field(default_factory=list)
    attestations: dict = field(default_factory=dict)

def empty_summary():
    return {"outcomes": "", "guards": {}, "trajectory_state": None}

def _guard(summary, gid):
    return summary["guards"].setdefault(
        gid, {"punya": 0.0, "proven": 0, "refused": 0, "classes": [], "refused_classes": {}})

def fold(summary, records, audits):
    """Carry state forward over an erased segment. Everything the guard,
    adversary and drift monitor read from erased entries lands here."""
    s = json.loads(json.dumps(summary))
    events = [(a.epoch, 0, i, True) for i, a in enumerate(audits)]
    events += [(r.index, 1, i, r.verdict_kind == "LEARNING") for i, r in enumerate(records)]
    s["outcomes"] += "".join("1" if refused else "0" for *_, refused in sorted(events))
    for r in records:
        g = _guard(s, r.guard_id)
        g["punya"] += r.punya_delta; g["proven"] += 1
        if r.class_id and r.verdict_kind in ("LAWFUL", "LEARNING") and r.class_id not in g["classes"]:
            g["classes"] = sorted(g["classes"] + [r.class_id])
    for a in audits:
        g = _guard(s, a.guard_id); g["refused"] += 1
        base = a.class_id.split(":shoshin-")[0]
        g["refused_classes"][base] = g["refused_classes"].get(base, 0) + 1
    if records: s["trajectory_state"] = list(records[-1].trajectory_state)
    return s

def _canon(s): return json.dumps(s, sort_keys=True, separators=(",", ":"))

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
    if last is not None and cut_epoch <= last.cut_epoch:
        raise CompressionError(f"cut {cut_epoch} is not past the last checkpoint ({last.cut_epoch})")
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
    summary = fold(last.summary if last else empty_summary(), recs, auds)
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
        signer_id=signer.id)
    cp = replace(cp, signature=signer.sign(cp.payload()).hex())
    keep_r, keep_a = ledger.records[len(recs):], ledger.audits[len(auds):]
    erased_att = _cited(recs, auds) - _cited(keep_r, keep_a)
    archive = Archive(cp.hash(), list(recs), list(auds),
                      {h: ledger.attestations[h] for h in erased_att if h in ledger.attestations})
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
    if _canon(fold(previous_summary or empty_summary(), recs, auds)) != checkpoint.summary_json:
        return False, "carried summary does not match the archived entries"
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
