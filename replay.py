
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
from cw_vfs import CapabilityDirJail, ConfinementViolation, clone_confined_snapshot

class Unreplayable(Exception): pass

class Snapshot:
    """The workdir as it was before the run, copied by the co-signer itself."""
    def __init__(self, workdir, root, copy):
        self.workdir, self.root, self.copy = workdir, root, copy

class SpaceSnapshot:
    """The workdir as it was before the run, copied by the co-signer's own
    monitor process (monitor.py): a space it holds, which only it can read."""
    def __init__(self, workdir, monitor, space):
        self.workdir, self.monitor, self.space = workdir, monitor, space

def take_in(monitor):
    import monitor as monitor_mod
    try: return SpaceSnapshot(monitor.workdir, monitor, monitor.open_space("real", "snapshot"))
    except monitor_mod.SpaceError as e: raise Unreplayable(f"workdir rejected by CW-VFS snapshot: {e}")

def take(workdir):
    workdir = os.path.realpath(workdir)
    root = tempfile.mkdtemp(prefix="snapshot_")
    copy = os.path.join(root, "w")
    try:
        if os.path.isdir(workdir):
            clone_confined_snapshot(workdir, copy)
        else:
            os.mkdir(copy)
    except ConfinementViolation as e:
        shutil.rmtree(root, ignore_errors=True)
        raise Unreplayable(f"workdir rejected by CW-VFS snapshot: {e}")
    return Snapshot(workdir, root, copy)

def release(snapshot):
    if isinstance(snapshot, SpaceSnapshot):
        import monitor as monitor_mod
        try: snapshot.monitor.close_space(snapshot.space)
        except monitor_mod.MonitorGone: pass
        return
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

def _replay_in_space(evidence, snapshot, workdir):
    """replay(), in a fresh copy of the snapshot that the co-signer's own
    monitor makes and runs. The raw trace comes back unread, and the
    co-signer reads it with its own parser (witness.parse)."""
    import monitor as monitor_mod
    mon = snapshot.monitor
    try: work = mon.open_space(snapshot.space, "replay")
    except monitor_mod.SpaceError as e: raise Unreplayable(f"snapshot copy rejected by CW-VFS: {e}")
    except monitor_mod.MonitorGone as e: raise Unreplayable(f"the co-signer's monitor is gone: {e}")
    calls = []
    try:
        for tool, kwargs, result in evidence["calls"]:
            if tool == "shell" and isinstance(result, dict) and result.get("jailed"):
                cmd = kwargs.get("cmd", "")
                ran = mon.call("shell", space=work, cmd=cmd)["result"]
                if not ran.get("jailed"):
                    raise Unreplayable(f"could not run the replay: {ran.get('error', 'not jailed')}")
                events = witness.parse({int(p): t for p, t in ran["trace"].items()}, cmd)
                if events is None:
                    raise Unreplayable("the replay's trace never shows the command starting")
                result = {"jailed": True, "events": events}
            elif tool == "file_write" and isinstance(result, dict) and result.get("ok"):
                raw_path = str(kwargs.get("path", ""))
                if raw_path and not os.path.isabs(raw_path):
                    raw_path = os.path.join(workdir, raw_path)
                wrote = mon.call("file_write", space=work, path=raw_path,
                                 content=kwargs.get("content", ""))["result"]
                if not wrote.get("ok"):
                    raise Unreplayable(f"replay file_write violated CW-VFS: {wrote.get('error')}")
                rec_sha = result.get("content_sha256")
                if rec_sha is not None and rec_sha != wrote["content_sha256"]:
                    raise Unreplayable(f"replayed content_sha256 {wrote['content_sha256'][:12]}... "
                                       f"!= recorded {rec_sha[:12]}...: the record's write was tampered with")
                result = dict(result, content_sha256=wrote["content_sha256"],
                              capability_witness=wrote["capability_witness"])
            calls.append((tool, kwargs, result))
    except monitor_mod.MonitorGone as e:
        raise Unreplayable(f"the co-signer's monitor is gone: {e}")
    finally:
        try: mon.close_space(work)
        except monitor_mod.MonitorGone: pass
    from critic_loop import effects_from_evidence
    return effects_from_evidence({"workdir": workdir, "predicted": evidence["predicted"],
                                  "policy": evidence.get("policy"), "calls": calls})

def replay(evidence, snapshot):
    """The effects of running the record's calls again, in order, against a
    fresh copy of the snapshot. Raises Unreplayable rather than guess."""
    from critic_loop import effects_from_evidence
    workdir = os.path.realpath(evidence["workdir"])
    if workdir != snapshot.workdir:
        raise Unreplayable("the snapshot is of another workdir")
    if isinstance(snapshot, SpaceSnapshot):
        return _replay_in_space(evidence, snapshot, workdir)
    if shutil.which("bwrap") is None or shutil.which("strace") is None:
        raise Unreplayable("bwrap and strace are both required to replay")
    scratch = tempfile.mkdtemp(prefix="replay_")
    work = os.path.join(scratch, "w")
    try:
        try:
            clone_confined_snapshot(snapshot.copy, work)
        except ConfinementViolation as e:
            raise Unreplayable(f"snapshot copy rejected by CW-VFS: {e}")
        with CapabilityDirJail(work, logical_workdir=workdir) as vfs:
            calls = []
            for tool, kwargs, result in evidence["calls"]:
                if tool == "shell" and isinstance(result, dict) and result.get("jailed"):
                    cmd = kwargs.get("cmd", "")
                    events = witness.parse(_traced(cmd, work, workdir), cmd)
                    if events is None:
                        raise Unreplayable("the replay's trace never shows the command starting")
                    result = {"jailed": True, "events": events}
                elif tool == "file_write" and isinstance(result, dict) and result.get("ok"):
                    # Written in-process the first time; replay it via CW-VFS. The
                    # recorded path is anchored to the workdir it names, and the
                    # jail - not a CWD-relative guess - decides confinement: a
                    # path outside the workdir is refused, not skipped.
                    raw_path = str(kwargs.get("path", ""))
                    if raw_path and not os.path.isabs(raw_path):
                        raw_path = os.path.join(workdir, raw_path)
                    try:
                        raw = kwargs.get("content", "").encode("utf-8")
                        wit = vfs.write_bytes_atomic(raw_path, raw)
                        rec_sha = result.get("content_sha256")
                        if rec_sha is not None and rec_sha != wit.content_sha256:
                            raise Unreplayable(f"replayed content_sha256 {wit.content_sha256[:12]}... "
                                               f"!= recorded {rec_sha[:12]}...: the record's write was tampered with")
                        result = dict(
                            result,
                            content_sha256=wit.content_sha256,
                            capability_witness=wit.to_dict(),
                        )
                    except ConfinementViolation as e:
                        raise Unreplayable(f"replay file_write violated CW-VFS: {e}")
                calls.append((tool, kwargs, result))
        return effects_from_evidence({"workdir": workdir, "predicted": evidence["predicted"],
                                      "policy": evidence.get("policy"),
                                      "calls": calls})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
