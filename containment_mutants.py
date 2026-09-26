#!/usr/bin/env python3
"""Mutation-test the jail's containment: break one bubblewrap flag at a time
and check that a containment probe catches it.

    python3 containment_mutants.py [--json]

For each mutant, a copy of this repository is made with one edit to
jail._bwrap, and tests/test_containment.py runs against the copy. A mutant is
caught only when a probe fails with ESCAPE:, meaning it saw the broken jail let
something out. A jail that merely fails to start is not a catch, because a
guard that passes for the wrong reason is worse than none. The probes touch
only things the test owns, so running a broken jail is safe, as root or not.

Some flags cannot be caught by any probe here, and each is named with its
reason rather than skipped silently:
    equivalent   the jail is exactly as contained without it, in this mode
    untested     what it prevents cannot be observed from a probe here

Exit codes:
    0  the unmutated jail passes every probe and every mutant was caught
    1  a mutant survived, or the unmutated jail failed a probe (named)
There is no transient exit: nothing here touches the network.
"""
import argparse, json, os, shutil, subprocess, sys, tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROBES = "tests/test_containment.py"

# (name, what breaks, text in jail.py, replacement)
MUTANTS = [
    ("root writable", "the host filesystem is writable",
     '"--ro-bind", "/", "/"', '"--bind", "/", "/"'),
    ("parent bound", "the workdir's parent is bound writable, not the workdir",
     '"--bind", s, w,', '"--bind", os.path.dirname(s), os.path.dirname(w),'),
    ("network shared", "the jail shares the host's network namespace",
     '"--unshare-all",', '"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try",'),
    ("pids shared", "the jail shares the host's PID namespace",
     '"--unshare-all",', '"--unshare-user", "--unshare-ipc", "--unshare-net", "--unshare-uts", "--unshare-cgroup-try",'),
    ("host /proc", "the jail sees the host's /proc",
     '"--proc", "/proc", ', ''),
    ("host /dev", "the jail sees the host's devices",
     '"--dev", "/dev", ', ''),
    ("outlives parent", "the jail's processes survive a stopped run",
     '"--die-with-parent",', ''),
    ("environment kept", "the jail inherits the host's environment",
     '"--clearenv", ', ''),
    ("capabilities kept", "the jail keeps its capabilities",
     '"--cap-drop", "ALL",', ''),
]

def equivalent():
    out = {"--tmpfs /tmp": "with the root read-only, a jail without a /tmp of its own cannot "
                           "write the host's either; the tmpfs is there so programs can work"}
    if os.geteuid() != 0:
        out["--cap-drop ALL"] = ("an unprivileged bubblewrap drops every capability itself; the "
                                 "flag matters only when the jail is started as root")
    return out

UNTESTED = {
    "--new-session": "stops a command injecting keystrokes into the terminal it was started "
                     "from (TIOCSTI); the jail runs with pipes and no terminal, so no probe here "
                     "has one to inject into",
}

def _copy():
    d = Path(tempfile.mkdtemp(prefix="containment_")) / "repo"
    shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"))
    return d

def _probe(repo):
    """(escapes, other_failures, passed) from running the probes in `repo`."""
    xml = repo / "report.xml"
    env = {**os.environ, "DHARMA_REQUIRE_JAIL": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", PROBES,
                    f"--junitxml={xml}"], cwd=repo, env=env, capture_output=True, text=True, timeout=600)
    escapes, others, passed = [], [], 0
    for case in ET.parse(xml).iter("testcase"):
        bad = case.find("failure") if case.find("failure") is not None else case.find("error")
        if bad is None:
            passed += 1 if case.find("skipped") is None else 0; continue
        text = (bad.get("message") or "") + (bad.text or "")
        (escapes if "ESCAPE:" in text else others).append(case.get("name"))
    return escapes, others, passed

def run():
    results, eq = [], equivalent()
    base = _copy()
    try: b_esc, b_other, b_pass = _probe(base)
    finally: shutil.rmtree(base.parent, ignore_errors=True)
    for name, breaks, old, new in MUTANTS:
        flag = old.replace('"', "").replace(",", "").strip()
        if any(flag.startswith(k) or k in flag for k in eq):
            results.append({"mutant": name, "breaks": breaks, "status": "equivalent",
                            "why": next(v for k, v in eq.items() if flag.startswith(k) or k in flag)})
            continue
        repo = _copy()
        try:
            src = (repo / "jail.py").read_text()
            if src.count(old) != 1:
                results.append({"mutant": name, "breaks": breaks, "status": "stale",
                                "why": f"jail.py no longer contains {old!r} exactly once"})
                continue
            (repo / "jail.py").write_text(src.replace(old, new))
            esc, other, _ = _probe(repo)
        finally: shutil.rmtree(repo.parent, ignore_errors=True)
        results.append({"mutant": name, "breaks": breaks,
                        "status": "caught" if esc else "SURVIVED",
                        "caught_by": esc, "other_failures": other})
    for flag, why in eq.items():
        if not any(r["status"] == "equivalent" and r["why"] == why for r in results):
            results.append({"mutant": flag, "breaks": "", "status": "equivalent", "why": why})
    for flag, why in UNTESTED.items():
        results.append({"mutant": flag, "breaks": "", "status": "untested", "why": why})
    baseline = {"passed": b_pass, "escapes": b_esc, "other_failures": b_other}
    ok = not b_esc and not b_other and b_pass > 0 and \
        all(r["status"] in ("caught", "equivalent", "untested") for r in results)
    return ok, baseline, results

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if shutil.which("bwrap") is None or shutil.which("strace") is None:
        print("bwrap and strace are both required: nothing to mutate"); return 1
    ok, baseline, results = run()
    if args.json:
        print(json.dumps({"ok": ok, "root": os.geteuid() == 0, "baseline": baseline,
                          "mutants": results}, indent=2))
    else:
        print(f"running as {'root' if os.geteuid() == 0 else 'an unprivileged user'}")
        print(f"unmutated jail: {baseline['passed']} probe(s) pass"
              + (f"; FAILING {baseline['escapes'] + baseline['other_failures']}"
                 if baseline["escapes"] or baseline["other_failures"] else ""))
        for r in results:
            detail = ", ".join(r.get("caught_by", [])) or r.get("why", "")
            if r["status"] == "SURVIVED" and r.get("other_failures"):
                detail = "no probe saw an escape; failed without one: " + ", ".join(r["other_failures"])
            print(f"  {r['status']:10s} {r['mutant']:18s} {detail}")
        print("ALL CAUGHT" if ok else "NOT ALL CAUGHT")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
