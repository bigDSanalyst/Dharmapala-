#!/usr/bin/env python3
"""Verify a persisted Dharmapala ledger from the command line.

    python3 verify.py keys  LEDGER.json [--json]
    python3 verify.py check LEDGER.json --pins PINS.json [--pin SIGNER=KEYID ...] [--json]

`keys` prints each signer's key id as stored in the file. Record them when
you first have reason to trust the ledger - out of band, not in the ledger -
and pass them to `check` later. Pins taken from the file at check time prove
only that the file agrees with itself, so `check` refuses to pass without them.

`check` passes only when every signer in the file is pinned, the chains,
signatures and checkpoints verify, and doctor reports nothing BLOCK or
DEGRADED. LOOK and DRIFT findings are printed and do not fail the check.

Exit codes:
    0  verified
    1  not verified: named reason printed (a finding, a key mismatch, an
       unpinned or unverifiable signer, an unreadable or unknown file)
There is no transient exit: nothing here touches the network.
"""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

FAIL_LEVELS = ("BLOCK", "DEGRADED")

def stored_keys(path):
    """(signer, scheme, key_id or None) for every signer the file names."""
    import hashlib
    data = json.loads(Path(path).read_text())
    out = []
    for sid, v in sorted(data.get("verifiers", {}).items()):
        kid = hashlib.sha256(bytes.fromhex(v["public"])).hexdigest() if v.get("public") else None
        out.append((sid, v.get("scheme", "?"), kid))
    return out

def read_pins(files, pairs):
    pins = {}
    for f in files or []:
        loaded = json.loads(Path(f).read_text())
        if not isinstance(loaded, dict): raise ValueError(f"{f}: pins must be a JSON object")
        pins.update(loaded)
    for p in pairs or []:
        if "=" not in p: raise ValueError(f"--pin {p!r}: expected SIGNER=KEYID")
        k, v = p.split("=", 1); pins[k] = v
    return pins

def check(path, pins):
    """Returns (ok, lines, findings) - lines are the reasons, in order."""
    from doctor import observe_with_drift
    from ledger import KeyMismatch, Ledger
    lines = []
    keys = stored_keys(path)
    named = {sid for sid, _, _ in keys}
    no_key = [sid for sid, _, kid in keys if kid is None]
    if no_key:
        lines.append(f"{', '.join(no_key)}: signs with a shared secret (HMAC), which has no public "
                     "key; nothing outside the process holding it can check these signatures")
    unpinned = [sid for sid, _, kid in keys if kid is not None and sid not in pins]
    if unpinned:
        lines.append(f"{', '.join(unpinned)}: no pinned key. Pass the key id you recorded "
                     "(`verify.py keys` prints the ids stored in the file)")
    stray = sorted(set(pins) - named)
    if stray:
        lines.append(f"pinned signer(s) {', '.join(stray)} do not appear in this ledger")
    try:
        L = Ledger.load(str(path), pinned={k: v for k, v in pins.items() if k in named})
    except KeyMismatch as e:
        return False, lines + [str(e)], []
    token, findings = observe_with_drift(L)
    failing = [f for f in findings if f.level in FAIL_LEVELS]
    for f in failing: lines.append(f"{f.level} {f.name}: {f.reason}")
    return not lines, lines, findings

def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a persisted Dharmapala ledger.")
    ap.add_argument("command", choices=["keys", "check"])
    ap.add_argument("ledger", type=Path)
    ap.add_argument("--pins", action="append", help="JSON file mapping signer -> key id")
    ap.add_argument("--pin", action="append", help="SIGNER=KEYID (repeatable)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if not args.ledger.is_file(): raise FileNotFoundError(f"{args.ledger}: no such file")
        if args.command == "keys":
            keys = stored_keys(args.ledger)
            if args.json:
                print(json.dumps({sid: kid for sid, _, kid in keys if kid}, indent=2, sort_keys=True))
            else:
                for sid, scheme, kid in keys:
                    print(f"{sid:20s} {scheme:14s} {kid or '(no public key: shared secret)'}")
            return 0
        pins = read_pins(args.pins, args.pin)
        ok, reasons, findings = check(args.ledger, pins)
    except (OSError, ValueError, KeyError, TypeError) as e:
        # A file this tool cannot read is not a ledger that failed: say which.
        msg = f"cannot verify {args.ledger}: {e.__class__.__name__}: {e}"
        print(json.dumps({"verified": False, "reasons": [msg]}) if args.json else msg)
        return 1
    if args.json:
        print(json.dumps({"verified": ok, "reasons": reasons,
                          "findings": [{"level": f.level, "name": f.name, "reason": f.reason}
                                       for f in findings]}, indent=2))
    else:
        for f in findings:
            if f.level not in FAIL_LEVELS: print(f"  {f.level:8s} {f.name}: {f.reason}")
        for r in reasons: print(f"  FAIL     {r}")
        print("VERIFIED" if ok else "NOT VERIFIED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
