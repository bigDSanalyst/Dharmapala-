#!/usr/bin/env python3
"""Mutation-test the jail's containment: break one bubblewrap flag, or one
part of confine.py, at a time and check that a containment probe catches it.

    python3 containment_mutants.py [--json]

For each mutant, a copy of this repository is made with one edit to
jail._bwrap or confine.py, and tests/test_containment.py runs against the copy.
The jail has two layers, and each is tested on its own, with the other out of
the way: bubblewrap's flags are broken with confine.py switched off, and
confine.py is broken with bubblewrap mounting the whole host read-only (as it
once did). Otherwise either layer would stop what the other is there to stop
and hide the break. A mutant is
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

# (name, what breaks, file, text in it, replacement)
MUTANTS = [
    ("host root bound", "the jail sees the whole host filesystem", "jail.py",
     '["bwrap", *_system_binds(),', '["bwrap", "--ro-bind", "/", "/",'),
    ("host root writable", "the host filesystem is mounted writable", "jail.py",
     '["bwrap", *_system_binds(),', '["bwrap", "--bind", "/", "/",'),
    ("all of /etc", "the jail sees every entry of /etc", "jail.py",
     'for e in _etc_entries():', 'for e in sorted(os.listdir("/etc")):'),
    ("parent bound", "the workdir's parent is bound writable, not the workdir", "jail.py",
     '"--bind", s, w,', '"--bind", os.path.dirname(s), os.path.dirname(w),'),
    ("network shared", "the jail shares the host's network namespace", "jail.py",
     '"--unshare-all",', '"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try",'),
    ("pids shared", "the jail shares the host's PID namespace", "jail.py",
     '"--unshare-all",', '"--unshare-user", "--unshare-ipc", "--unshare-net", "--unshare-uts", "--unshare-cgroup-try",'),
    ("host /proc", "the jail sees the host's /proc", "jail.py",
     '"--proc", "/proc", ', '"--ro-bind", "/proc", "/proc", '),
    ("host /dev", "the jail sees the host's devices", "jail.py",
     '"--dev", "/dev", ', '"--dev-bind", "/dev", "/dev", '),
    ("outlives parent", "the jail's processes survive a stopped run", "jail.py",
     '"--die-with-parent",', ''),
    ("environment kept", "the jail inherits the host's environment", "jail.py",
     '"--clearenv", ', ''),
    ("capabilities kept", "the jail keeps its capabilities", "jail.py",
     '"--cap-drop", "ALL",', ''),
    # confine.py, inside an intact bubblewrap jail
    ("landlock off", "the command runs without its Landlock ruleset", "confine.py",
     "    _landlock(libc, workdir)\n", ""),
    ("reads anywhere", "Landlock lets the command read the whole filesystem", "confine.py",
     'READ_ROOTS = ("/usr",', 'READ_ROOTS = ("/", "/usr",'),
    ("seccomp off", "calls the trace cannot see reach the kernel", "confine.py",
     "    _seccomp(libc)\n", ""),
    ("openat2 allowed", "the filter lets openat2 through", "confine.py",
     'DENIED = ("openat2", ', 'DENIED = ('),
    ("execveat allowed", "the filter lets execveat through", "confine.py",
     '"execveat", "io_uring_setup"', '"io_uring_setup"'),
    ("io_uring allowed", "the filter lets io_uring_setup through", "confine.py",
     '"io_uring_setup", "io_uring_enter"', '"io_uring_enter"'),
    ("unix sockets allowed", "the filter refuses another family, not AF_UNIX", "confine.py",
     'AF_UNIX = 1\n', 'AF_UNIX = 99\n'),
    ("wrong half read", "the filter reads the high word of socket()'s domain", "confine.py",
     'ARG0_LOW = 16', 'ARG0_LOW = 20'),
    ("all 64 bits compared", "the filter wants the domain's high word to be 0 too, so "
     "1 | 1 << 32, which the kernel reads as AF_UNIX, gets through", "confine.py",
     """    prog += [(BPF_JEQ_K, 0, 3, numbers["socket"]),     # not socket(): allow
             (BPF_LD_W_ABS, 0, 0, ARG0_LOW),            # the domain's low 32 bits
             (BPF_JEQ_K, 0, 1, AF_UNIX),""",
     """    prog += [(BPF_JEQ_K, 0, 5, numbers["socket"]),
             (BPF_LD_W_ABS, 0, 0, ARG0_LOW + 4), (BPF_JEQ_K, 0, 3, 0),
             (BPF_LD_W_ABS, 0, 0, ARG0_LOW), (BPF_JEQ_K, 0, 1, AF_UNIX),"""),
]

# Each file's mutants run with the other layer out of the way: the edit that
# does that, and the probes only that other layer passes. With the edit and no
# mutant, exactly those probes must see an escape and every other must pass,
# which shows the layer under test contains the jail alone, and that those
# probes really depend on the other one. They do not count as catching this
# layer's mutants.
LAYERS = {
    "jail.py": {"name": "bubblewrap alone (confine.py off)",
                "isolate": ("jail.py", "] + _confine(w)", "]"),
                "other_only": {"test_calls_the_trace_cannot_see_are_refused",
                               "test_unix_sockets_cannot_be_made"}},
    "confine.py": {"name": "confine.py alone (the whole host mounted read-only)",
                   "isolate": ("jail.py", '["bwrap", *_system_binds(),', '["bwrap", "--ro-bind", "/", "/",'),
                   "other_only": {"test_host_directories_are_not_there",
                                  "test_only_listed_etc_entries_are_there"}},
}

def equivalent():
    out = {"--tmpfs /tmp": "the jail's root is its own, so without the tmpfs /tmp is a directory "
                           "of the jail's, not the host's /tmp; the tmpfs is there so programs can work"}
    if os.geteuid() != 0:
        out["--cap-drop ALL"] = ("an unprivileged bubblewrap drops every capability itself; the "
                                 "flag matters only when the jail is started as root")
    return out

UNTESTED = {
    "--new-session": "stops a command injecting keystrokes into the terminal it was started "
                     "from (TIOCSTI); the jail runs with pipes and no terminal, so no probe here "
                     "has one to inject into",
    "--ro-bind /usr": "the system directories are bound read-only; a probe would have to write "
                      "the host's /usr to see a writable bind, which an unprivileged test user "
                      "cannot do and a root one must not (a writable host root is caught above)",
    "file handles": "open_by_handle_at needs CAP_DAC_READ_SEARCH, which the jail never holds, so "
                    "no probe here could open a file that way to see the filter stop it",
    "compat calls": "32-bit and x32 system calls are refused by the filter's arch and x32 checks "
                    "(tests/test_confine.py runs the filter over them); no probe here makes one",
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

def _probe_edited(edits):
    """_probe on a copy with `edits` [(file, old, new)] applied, or (None, why)
    when one of them no longer matches exactly once."""
    repo = _copy()
    try:
        for f, old, new in edits:
            src = (repo / f).read_text()
            if src.count(old) != 1:
                return None, f"{f} no longer contains {old!r} exactly once"
            (repo / f).write_text(src.replace(old, new))
        return _probe(repo), ""
    finally: shutil.rmtree(repo.parent, ignore_errors=True)

def run():
    results, eq = [], equivalent()
    (b_esc, b_other, b_pass), _ = _probe_edited([])
    alone = {}
    for f, layer in LAYERS.items():
        r, why = _probe_edited([layer["isolate"]])
        esc, other, passed = r if r else ([], [why], 0)
        alone[f] = {"layer": layer["name"], "passed": passed, "escapes": esc, "other_failures": other,
                    "ok": set(esc) == layer["other_only"] and not other and passed > 0}
    for name, breaks, f, old, new in MUTANTS:
        flag = old.replace('"', "").replace(",", "").strip()
        if any(flag.startswith(k) or k in flag for k in eq):
            results.append({"mutant": name, "breaks": breaks, "status": "equivalent",
                            "why": next(v for k, v in eq.items() if flag.startswith(k) or k in flag)})
            continue
        r, why = _probe_edited([(f, old, new), LAYERS[f]["isolate"]])
        if r is None:
            results.append({"mutant": name, "breaks": breaks, "status": "stale", "why": why})
            continue
        esc, other, _ = r
        caught = [e for e in esc if e not in LAYERS[f]["other_only"]]
        results.append({"mutant": name, "breaks": breaks,
                        "status": "caught" if caught else "SURVIVED",
                        "caught_by": caught, "other_failures": other})
    for flag, why in eq.items():
        if not any(r["status"] == "equivalent" and r["why"] == why for r in results):
            results.append({"mutant": flag, "breaks": "", "status": "equivalent", "why": why})
    for flag, why in UNTESTED.items():
        results.append({"mutant": flag, "breaks": "", "status": "untested", "why": why})
    baseline = {"passed": b_pass, "escapes": b_esc, "other_failures": b_other, "alone": alone}
    ok = not b_esc and not b_other and b_pass > 0 and all(a["ok"] for a in alone.values()) and \
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
        for f, a in baseline["alone"].items():
            print(f"{a['layer']}: {a['passed']} probe(s) pass; escapes {sorted(a['escapes'])}"
                  + ("" if a["ok"] else f" - EXPECTED exactly {sorted(LAYERS[f]['other_only'])} "
                                        f"and no other failures, got {a['other_failures']}"))
        for r in results:
            detail = ", ".join(r.get("caught_by", [])) or r.get("why", "")
            if r["status"] == "SURVIVED" and r.get("other_failures"):
                detail = "no probe saw an escape; failed without one: " + ", ".join(r["other_failures"])
            print(f"  {r['status']:10s} {r['mutant']:18s} {detail}")
        print("ALL CAUGHT" if ok else "NOT ALL CAUGHT")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
