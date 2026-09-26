
# Co-signer re-execution: the co-signer runs the plan again itself.
#
# Re-deriving effects from the run record (witness.py) catches a guard that
# misreads the trace. It cannot catch a trace that lies: an executor or jail
# that drops the line where /etc/shadow was opened hands both parsers the same
# clean story. So a co-signer that re-executes does not take the trace on
# trust. Before the run it copies the workdir for itself (take); after it,
# it runs the record's calls again against a fresh copy of that snapshot,
# traced by its own invocation of bubblewrap and strace and read by its own
# parser, and derives the effects from what it saw.
#
# The copy is mounted at the workdir's own path, so the command sees the same
# paths, the same $PWD and the same files it saw the first time: a replay is
# not something a command can tell apart from the run it replays. What it
# shares with the executor is the machine: the same bwrap and strace
# binaries and the same kernel. A co-signer on another machine is the full
# version of this; the protocol does not change.
import os, shutil, subprocess, tempfile

import jail, witness

class Unreplayable(Exception): pass

class Snapshot:
    """The workdir as it was before the run, copied by the co-signer itself."""
    def __init__(self, workdir, root, copy):
        self.workdir, self.root, self.copy = workdir, root, copy

def take(workdir):
    workdir = os.path.realpath(workdir)
    root = tempfile.mkdtemp(prefix="snapshot_")
    copy = os.path.join(root, "w")
    if os.path.isdir(workdir): shutil.copytree(workdir, copy, symlinks=True)
    else: os.mkdir(copy)
    return Snapshot(workdir, root, copy)

def release(snapshot):
    shutil.rmtree(snapshot.root, ignore_errors=True)

def _traced(cmd, source, workdir, timeout=None):
    """{pid: raw strace text} for `sh -c cmd` with `source` mounted at `workdir`."""
    tdir = tempfile.mkdtemp(prefix="replaytrace_"); trace = os.path.join(tdir, "t")
    argv = ["strace", "-ff", "-qq", "-y", "--decode-pids=pidns", "-s", "4096",
            "-e", f"trace={jail.SYSCALLS}", "-o", trace,
            *jail._bwrap(workdir, source=source), "sh", "-c", cmd]
    try:
        try: subprocess.run(argv, capture_output=True, text=True,
                            timeout=jail.TIMEOUT if timeout is None else timeout)
        except subprocess.TimeoutExpired: pass     # what it did until then is still in the trace
        return {int(f.rsplit(".", 1)[1]): open(os.path.join(tdir, f)).read()
                for f in os.listdir(tdir) if f.startswith("t.")}
    except OSError as e:
        raise Unreplayable(f"could not run the replay: {e}")
    finally:
        shutil.rmtree(tdir, ignore_errors=True)

def _inside(path, workdir):
    p = os.path.normpath(path if os.path.isabs(path) else os.path.join(workdir, path))
    return os.path.relpath(p, workdir) if p == workdir or p.startswith(workdir + os.sep) else None

def replay(evidence, snapshot):
    """The effects of running the record's calls again, in order, against a
    fresh copy of the snapshot. Raises Unreplayable rather than guess."""
    from critic_loop import effects_from_evidence
    workdir = os.path.realpath(evidence["workdir"])
    if workdir != snapshot.workdir:
        raise Unreplayable("the snapshot is of another workdir")
    if shutil.which("bwrap") is None or shutil.which("strace") is None:
        raise Unreplayable("bwrap and strace are both required to replay")
    scratch = tempfile.mkdtemp(prefix="replay_")
    work = os.path.join(scratch, "w")
    try:
        shutil.copytree(snapshot.copy, work, symlinks=True)
        calls = []
        for tool, kwargs, result in evidence["calls"]:
            if tool == "shell" and isinstance(result, dict) and result.get("jailed"):
                cmd = kwargs.get("cmd", "")
                events = witness.parse(_traced(cmd, work, workdir), cmd)
                if events is None:
                    raise Unreplayable("the replay's trace never shows the command starting")
                result = {"jailed": True, "events": events}
            elif tool == "file_write" and isinstance(result, dict) and result.get("ok"):
                # Written in-process the first time; write it again so the
                # calls after it see the same files. Outside the workdir it is
                # not written again: its effect comes from its path.
                rel = _inside(kwargs.get("path", ""), workdir)
                if rel is not None:
                    target = os.path.join(work, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "w") as f: f.write(kwargs.get("content", ""))
            calls.append((tool, kwargs, result))
        return effects_from_evidence({"workdir": workdir, "predicted": evidence["predicted"],
                                      "calls": calls})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
