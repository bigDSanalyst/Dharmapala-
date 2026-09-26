#!/usr/bin/env python3
"""Bitcoin timestamps for compression checkpoints (OpenTimestamps, ots CLI).

A checkpoint says what was erased and what state carried forward, but not
when: its signer chooses every field. This anchors each checkpoint in
Bitcoin: its canonical JSON is written to <dir>/NNNN-<hash16>.json, an entry
is appended to <dir>/log.jsonl (an append-only hash chain), and the file is
stamped with the ots command-line client. Once a stamp is upgraded into a
Bitcoin block, the checkpoint provably existed no later than that block.
That is an upper bound only: it does not say the checkpoint was made then.

Ported from syndicate-genesis tools/anchor.py (commit 455a1c4), the mold for
the syndicate repos, including its four hard-won distinctions: a calendar
that did not answer is not a timestamp that is "not yet confirmed" (row 62);
an ots that is installed but will not run is a human's problem, not a
transient (row 73); `run` records while `upgrade` finds out, so they do not
share an exit discipline (row 74); and an anchor that could not be submitted
is one nothing was established about, so `upgrade` does not exit 0 on it
(row 76). Keep the ots helpers in step with the mold rather than fixing them
only here: a bug found in them is the mold's bug first.

What differs from the mold is only what is anchored: the mold stamps a
manifest of repository files; this stamps each compression checkpoint's
canonical JSON, and `verify` also checks the exports against a ledger.

Where it runs: next to the persisted ledger, wherever a deployment keeps it.
`run` after each compression; `upgrade` on a schedule (a few hours apart is
plenty; a Bitcoin confirmation takes hours) until every anchor is confirmed.
`verify.py check --anchors DIR` checks the anchors along with the ledger.

Exit codes:
    0  done: every anchor's state was established
    1  needs a human: a broken chain or tampered file on `verify`, an anchor
       unsubmitted past the stale window, or an ots that will not run
    2  transient: the calendars could not be reached, so some anchors' state
       is unknown. NOT the same as unconfirmed.

Commands: run (record new checkpoints, try to stamp), upgrade, verify.
"""
import argparse, hashlib, json, re, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

STALE_DAYS = 14
CORE_FIELDS = ["seq", "checkpoint_hash", "file", "file_sha256", "prev", "created"]

def sha256_file(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))
def core_hash(entry): return hashlib.sha256(canonical({k: entry[k] for k in CORE_FIELDS}).encode()).hexdigest()

def load_log(log_path):
    if not log_path.exists(): return []
    return [json.loads(ln) for ln in log_path.read_text().splitlines() if ln.strip()]

def rewrite_log(log_path, entries):
    log_path.write_text("".join(canonical(e) + "\n" for e in entries))

def load_checkpoints(ledger_path):
    """The checkpoints a persisted ledger holds, decoded as the ledger decodes
    them. Not verified here: that is verify.py's job (and --anchors joins them)."""
    from ledger import _dec, _types
    data = json.loads(Path(ledger_path).read_text())
    if data.get("format") != "dharmapala-ledger/v2":
        raise ValueError(f"{ledger_path}: not a dharmapala-ledger/v2 file")
    return _dec(data.get("checkpoints", []), _types())

def record(checkpoints, anchor_dir):
    """Append a log entry and an export file for each checkpoint not yet
    anchored. Returns the new entries."""
    anchor_dir.mkdir(parents=True, exist_ok=True)
    log_path = anchor_dir / "log.jsonl"
    entries = load_log(log_path)
    done = {e["checkpoint_hash"] for e in entries}
    new = []
    for cp in checkpoints:
        h = cp.hash()
        if h in done: continue
        prev = entries[-1] if entries else None
        seq = prev["seq"] + 1 if prev else 1
        name = f"{seq:04d}-{h[:16]}.json"
        (anchor_dir / name).write_bytes(canonical(cp.__dict__).encode())
        e = {"seq": seq, "checkpoint_hash": h, "file": name,
             "file_sha256": sha256_file(anchor_dir / name),
             "prev": core_hash(prev) if prev else None, "status": "unsubmitted", "created": now()}
        with log_path.open("a") as f: f.write(canonical(e) + "\n")
        entries.append(e); new.append(e); done.add(h)
        print(f"anchor #{seq:04d}: checkpoint {h[:16]}")
    return new

# --- ots helpers: kept in step with syndicate-genesis tools/anchor.py ------------------

BROKEN_INSTALL = "ots-broken-install"

def ots_cli():
    path = shutil.which("ots")
    if path is None:
        print("ots CLI not found (pip install opentimestamps-client); entries recorded, stamps deferred")
    return path

def run_ots(*args):
    """Run ots; a timeout, a broken install and a real answer are different
    things (the mold's row 73)."""
    try:
        return subprocess.run(["ots", *args], capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="ots timed out")
    except OSError as e:
        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout="",
            stderr=BROKEN_INSTALL + ": ots is on PATH but will not execute (%s). Reinstall it - "
                   "`pip install --force-reinstall opentimestamps-client` - this is not a network "
                   "problem and retrying will not help." % e.__class__.__name__)

# A calendar we could not talk to is not a calendar that told us "not yet".
# Read as an allowlist of known-good statuses: anything unrecognised becomes
# "could not look", which is the safe direction.
CALENDAR_LINE = re.compile(r"^Calendar\s+(\S+):\s*(.+)$", re.M)
CALENDAR_OK = ("pending", "attestation", "complete", "success")

def calendars_answered(r):
    if r is None: return False, "ots was never run"
    text = (r.stderr or "") + "\n" + (r.stdout or "")
    problems = [(u, t.strip()) for u, t in CALENDAR_LINE.findall(text)
                if not any(k in t.lower() for k in CALENDAR_OK)]
    if problems: return False, "%s: %s" % problems[0]
    if r.returncode != 0 and not CALENDAR_LINE.search(text):
        tail = [l for l in text.strip().splitlines() if l.strip()]
        return False, (tail[-1] if tail else "ots exited %d with no output" % r.returncode)
    return True, ""

def parse_info(text):
    out = {"digest": None, "confirmed": False, "height": None}
    if not text: return out
    m = re.search(r"File sha256 hash:\s*([0-9a-f]+)", text)
    if m: out["digest"] = m.group(1)
    heights = [int(h) for h in re.findall(r"BitcoinBlockHeaderAttestation\((\d+)\)", text)]
    if heights: out["confirmed"] = True; out["height"] = min(heights)
    return out

def info_for(ots_path):
    r = run_ots("info", str(ots_path))
    return None if r.returncode != 0 else r.stdout + r.stderr

def ensure_stamps(anchor_dir):
    """Number of anchors whose state could not be established; -1 when ots is
    installed but will not run (a human's job, not a retry)."""
    log_path = anchor_dir / "log.jsonl"
    entries = load_log(log_path)
    if not ots_cli():
        return len([e for e in entries if e["status"] != "confirmed"])
    changed, unchecked, broken = False, 0, []
    for e in entries:
        f = anchor_dir / e["file"]; ots = Path(str(f) + ".ots")
        if not f.exists():
            print(f"error #{e['seq']:04d}: export file missing"); continue
        if not ots.exists():
            r = run_ots("stamp", str(f))
            if ots.exists():
                e["status"] = "pending"; changed = True
                print(f"submitted #{e['seq']:04d}")
            elif BROKEN_INSTALL in (r.stderr or ""):
                broken.append(f"{e['seq']:04d}")
            else:
                # Mold row 76: an anchor that could not be submitted is one
                # this run established nothing about, like one it could not
                # upgrade (row 62).
                answered, problem = calendars_answered(r)
                if answered:
                    tail = (r.stderr or r.stdout or "").strip().splitlines()
                    problem = tail[-1] if tail else "ots stamp failed with no output"
                unchecked += 1
                print(f"unsubmitted #{e['seq']:04d} - could not reach the calendars to submit it ({problem})")
        elif e["status"] != "confirmed":
            r = run_ots("upgrade", str(ots))
            answered, problem = calendars_answered(r)
            info = parse_info(info_for(ots))
            if e["status"] == "unsubmitted": e["status"] = "pending"; changed = True
            if info["digest"] and info["digest"] != e["file_sha256"]:
                print(f"error #{e['seq']:04d}: .ots covers different bytes than the log claims")
            if info["confirmed"]:
                e.update(status="confirmed", confirmed_at=now()); changed = True
                if info["height"]: e["height"] = info["height"]
                print(f"confirmed #{e['seq']:04d} in Bitcoin (block {info['height'] or '?'})")
            elif BROKEN_INSTALL in (r.stderr or ""):
                broken.append(f"{e['seq']:04d}")
            elif not answered:
                unchecked += 1
                print(f"unknown #{e['seq']:04d} - could not reach the calendars, so nothing was "
                      f"checked ({problem}). This is NOT 'not yet confirmed'.")
            else:
                print(f"pending #{e['seq']:04d} - not yet in a Bitcoin block")
    if changed: rewrite_log(log_path, entries)
    if broken:
        print("ots is installed but will not run, so anchors " + ", ".join(broken)
              + " were not checked. Reinstall opentimestamps-client; this is not a network problem.")
        return -1
    return unchecked

def stale_unsubmitted(anchor_dir):
    bad = []
    for e in load_log(anchor_dir / "log.jsonl"):
        if e["status"] == "unsubmitted":
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(e["created"].replace("Z", "+00:00"))).days
            if age > STALE_DAYS: bad.append(e["seq"])
    return bad

def verify(anchor_dir, checkpoints=None, say=print):
    """The chain is intact, every export is the checkpoint the log names, and
    (with checkpoints) every anchored checkpoint is one the ledger holds and
    every one the ledger holds is anchored."""
    entries = load_log(anchor_dir / "log.jsonl")
    ok, prev, cli = True, None, shutil.which("ots")
    held = {cp.hash(): cp for cp in (checkpoints or [])}
    for e in entries:
        tag = f"#{e['seq']:04d}"
        if e.get("prev") != prev: say(f"error {tag}: chain broken (prev mismatch)"); ok = False
        prev = core_hash(e)
        f = anchor_dir / e["file"]
        if not f.exists(): say(f"error {tag}: export missing"); ok = False; continue
        if sha256_file(f) != e["file_sha256"]: say(f"error {tag}: export digest mismatch - tampered?"); ok = False
        from compression import Checkpoint
        try: cp = Checkpoint(**json.loads(f.read_text()))
        except (TypeError, ValueError): say(f"error {tag}: export is not a checkpoint"); ok = False; continue
        if cp.hash() != e["checkpoint_hash"]: say(f"error {tag}: export is not the checkpoint the log names"); ok = False
        if checkpoints is not None and e["checkpoint_hash"] not in held:
            say(f"error {tag}: anchored checkpoint is not in this ledger"); ok = False
        ots = Path(str(f) + ".ots")
        if e["status"] != "unsubmitted" and not ots.exists():
            say(f"error {tag}: status {e['status']} but no .ots file"); ok = False
        if ots.exists() and cli:
            info = parse_info(info_for(ots))
            if info["digest"] and info["digest"] != e["file_sha256"]:
                say(f"error {tag}: .ots covers different bytes than the log claims"); ok = False
    if checkpoints is not None:
        missing = set(held) - {e["checkpoint_hash"] for e in entries}
        if missing: say(f"error: {len(missing)} checkpoint(s) never anchored"); ok = False
    n_conf = sum(1 for e in entries if e["status"] == "confirmed")
    say(f"{len(entries)} anchor(s), {n_conf} Bitcoin-confirmed - " + ("OK" if ok else "FAILURES PRESENT"))
    return ok

def main(argv=None):
    ap = argparse.ArgumentParser(description="Bitcoin timestamps for compression checkpoints (ots CLI).")
    ap.add_argument("command", choices=["run", "upgrade", "verify"])
    ap.add_argument("--ledger", type=Path, required=True, help="a persisted ledger JSON")
    ap.add_argument("--dir", type=Path, required=True, help="the anchor directory")
    args = ap.parse_args(argv)
    checkpoints = load_checkpoints(args.ledger)
    # `run` is asked to RECORD; stamping is best-effort and deferred, and a
    # stale unsubmitted anchor escalates to 1 below. `upgrade` is asked to FIND
    # OUT, so a run that could not look has failed at its only job (row 74).
    unchecked = 0
    if args.command == "run":
        record(checkpoints, args.dir); ensure_stamps(args.dir)
    elif args.command == "upgrade":
        unchecked = ensure_stamps(args.dir)
    else:
        return 0 if verify(args.dir, checkpoints) else 1
    stale = stale_unsubmitted(args.dir)
    if stale:
        print(f"error: anchors {stale} unsubmitted for more than {STALE_DAYS} days"); return 1
    if unchecked < 0: return 1
    if unchecked:
        print(f"{unchecked} anchor(s) could not be checked at all. Run again when the network "
              "is back; nothing is wrong with the chain.")
        return 2
    return 0

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
