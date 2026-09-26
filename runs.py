
# Run records: what each guarded call really did, kept next to the ledger.
#
# The ledger signs a digest of each run's record (the attestation's
# evidence_digest) but not the record itself, so what a call wrote, read or
# printed was gone once the run ended, and the model's own account of its work
# was the only one left. The model's account is a self-declared claim. In the
# first live runs a small model wrote a placeholder into a file and then
# reported the file's intended contents, and said "there are no credentials
# here" about a directory holding a .env it had been refused.
#
# So every call the gate sees becomes an entry in an append-only, hash-chained
# JSON-lines file: the call, what the gate decided, and, for a call that ran,
# the full run record whose digest the ledger signed. account() turns the
# entries into a plain account of what happened, built from them and never
# from the model, to set beside the model's answer. verify() checks the file
# against the ledger:
#   - the chain is intact: nothing edited, dropped from the middle or reordered
#   - every stored record hashes to the digest its entry names
#   - every entry that ran is one the ledger signed, with the verdict it says
#   - every run the ledger signed has an entry: none dropped from the end
#
# A call whose output was withheld from the model is not written in full
# either: what it read is exactly what must not leave, and a file on disk is
# one more way out. Its entry keeps the digest, which the ledger still signs.
import hashlib, json, os

FORMAT = "dharmapala-runs/v1"
GENESIS = "0" * 64
PREVIEW = 60

class RunsError(ValueError): pass

def _canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def _entry_hash(e):
    return hashlib.sha256(_canon({k: v for k, v in e.items() if k != "hash"}).encode()).hexdigest()

def _roundtrip(obj):
    # What will be read back is what is hashed: tuples in a record become lists.
    return json.loads(json.dumps(obj))

class RunLog:
    """The entries of one run, written to `path` (if any) as they happen."""
    def __init__(self, path=None):
        self.path = path
        self.entries = load(path) if path and os.path.exists(path) else []

    def add(self, call_id, tool, args, outcome, detail, evidence=None, withheld=False):
        from critic_loop import evidence_digest
        ev = _roundtrip(evidence) if evidence is not None else None
        e = {"format": FORMAT, "seq": len(self.entries), "call_id": call_id, "tool": tool,
             "args": _roundtrip(args), "outcome": outcome, "detail": detail,
             "evidence_digest": evidence_digest(ev) if ev is not None else None,
             "evidence": None if withheld else ev,
             "withheld": bool(withheld and ev is not None),
             "prev": self.entries[-1]["hash"] if self.entries else GENESIS}
        e["hash"] = _entry_hash(e)
        self.entries.append(e)
        if self.path:
            with open(self.path, "a") as f: f.write(_canon(e) + "\n")
        return e

def load(path):
    entries = []
    try:
        with open(path) as f:
            for n, line in enumerate(f, 1):
                if not line.strip(): continue
                try: entries.append(json.loads(line))
                except ValueError as e: raise RunsError(f"{path}:{n}: not JSON ({e})") from None
    except OSError as e:
        raise RunsError(f"{path}: {e}") from None
    return entries

def verify(entries, ledger):
    """Problems found checking the entries against themselves and the ledger;
    an empty list means they hold."""
    from critic_loop import evidence_digest
    problems, prev = [], GENESIS
    signed = {a.evidence_digest: a for a in ledger.attestations.values()
              if getattr(a, "evidence_digest", "")}
    for i, e in enumerate(entries):
        tag = f"run {i}"
        if not isinstance(e, dict) or e.get("format") != FORMAT:
            problems.append(f"{tag}: not a {FORMAT} entry"); continue
        if e.get("seq") != i: problems.append(f"{tag}: out of sequence (seq {e.get('seq')})")
        if e.get("prev") != prev: problems.append(f"{tag}: chain broken (does not follow the entry before it)")
        if e.get("hash") != _entry_hash(e): problems.append(f"{tag}: edited (its hash does not match it)")
        prev = e.get("hash")
        d = e.get("evidence_digest")
        if e.get("evidence") is not None and evidence_digest(e["evidence"]) != d:
            problems.append(f"{tag}: its run record does not hash to the digest it names")
        if d is not None:
            a = signed.get(d)
            if a is None:
                if e.get("outcome") in ("lawful", "learning"):
                    problems.append(f"{tag}: a run the ledger never signed")
            elif a.verdict.lower() != e.get("outcome"):
                problems.append(f"{tag}: says {e.get('outcome')}, the ledger signed {a.verdict}")
    seen = {e.get("evidence_digest") for e in entries if isinstance(e, dict)}
    missing = [d for d in signed if d not in seen]
    if missing: problems.append(f"{len(missing)} run(s) the ledger signed have no entry here")
    return problems

def _show(s):
    s = json.dumps(s)
    return s if len(s) <= PREVIEW else s[:PREVIEW - 4] + '..."'

def _what(tool, args):
    if not isinstance(args, dict): return _show(args)
    if tool == "shell": return _show(args.get("cmd", ""))
    if tool == "http_get": return args.get("url", "")
    return args.get("path", "")

def account(entries):
    """What happened, one line per call, from the entries alone."""
    lines = []
    for e in entries:
        tool, args, outcome = e.get("tool"), e.get("args"), e.get("outcome")
        what = _what(tool, args)
        if outcome == "lawful" and e.get("evidence"):
            result = e["evidence"]["calls"][-1][2]
            if tool == "file_read":
                line = f"read {what} -> {_show(result.get('content', ''))}" if result.get("ok") \
                    else f"tried to read {what}: {result.get('error')}"
            elif tool == "file_write":
                line = f"wrote {what} <- {_show(args.get('content', ''))} ({result.get('bytes')} bytes)" \
                    if result.get("ok") else f"tried to write {what}: {result.get('error')}"
            elif tool == "shell":
                line = f"ran {what} -> exit {result.get('returncode')}, printed {_show(result.get('stdout', ''))}"
            else:
                line = f"did not fetch {what} (the sandbox has no network)"
        elif e.get("withheld") or (e.get("evidence_digest") and outcome != "lawful"):
            line = f"{tool} {what}: ran contained, {outcome}; output withheld from the model"
        else:
            line = f"{tool} {what}: {e.get('detail', '')}"
        lines.append(f"{outcome:9s} {line}")
    return lines
