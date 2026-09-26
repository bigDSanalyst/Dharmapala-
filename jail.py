
# Real execution, observed. The critic judges a plan from a dry run, which
# cannot see what a command does once it runs: a script's contents, a
# command inside $(...), a symlink, behaviour that differs at run time. This
# runs an approved shell command for real, inside a jail, under strace, and
# turns what the trace shows into effects in the same vocabulary the Vow uses.
#
#   prevention   bubblewrap: the whole filesystem read-only except the
#                workdir, a fresh /tmp, no network, its own process and IPC
#                namespaces (kill -9 -1 reaches nothing outside), no new
#                privileges, killed with its parent
#   detection    strace -f: every exec, open, connect, unlink, rename and
#                kill, including the ones the jail refused. An attempt is
#                an effect: trying to write /etc is the harm the Vow names,
#                whether or not the jail let it land.
#
# Fail closed: without bwrap and strace nothing runs. Never "run it unjailed".
import os, re, shutil, subprocess, tempfile
from dataclasses import dataclass, field

from observation import (FILE_READERS, NETWORK_COMMANDS, PACKAGE_COMMANDS, VETTED_COMMANDS,
                         DESTRUCT_CMDS, DOMINATE_CMDS, _touch_host, _touch_path, inside, normalise)

TIMEOUT = 30.0
SYSCALLS = ("execve,openat,open,creat,connect,unlinkat,unlink,renameat,renameat2,rename,kill,"
            "clone,clone3,fork,vfork")
# Reads every dynamically linked program makes before it does anything. Not
# the plan's doing, so not the plan's effect. Anything else outside the
# workdir is read_outside_workdir, and every read is checked for sensitivity.
# Name-service files are here too: libc reads /etc/passwd to print a file's
# owner. A plan that names them (cat /etc/passwd) is still caught, from the
# command's own arguments; a program that opens them itself is not, and any
# such program is exec_unvetted already.
LOADER_READS = ("/etc/ld.so.", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/share/locale/",
                "/usr/lib/locale/", "/etc/localtime", "/usr/share/zoneinfo/", "/proc/self/",
                "/proc/filesystems", "/proc/mounts", "/dev/null", "/dev/tty", "/usr/share/terminfo/", "/lib/terminfo/",
                "/etc/terminfo/", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/hosts",
                "/etc/resolv.conf", "/etc/host.conf", "/etc/gai.conf", "/etc/locale.alias")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

class JailUnavailable(Exception): pass

@dataclass
class Execution:
    returncode: int; stdout: str; stderr: str
    events: list = field(default_factory=list)      # (kind, detail, succeeded)
    timed_out: bool = False

def available():
    """(True, "") when a jailed, traced run works on this machine, else (False, why)."""
    for tool in ("bwrap", "strace"):
        if shutil.which(tool) is None: return False, f"{tool} not installed"
    try:
        with tempfile.TemporaryDirectory() as d:
            r = run("true", d, _probe=True)
        if r.returncode != 0: return False, f"jail probe exited {r.returncode}: {r.stderr.strip()[-200:]}"
    except (JailUnavailable, OSError, subprocess.SubprocessError) as e:
        return False, f"jail probe failed: {e}"
    return True, ""

def _bwrap(workdir):
    w = os.path.realpath(workdir)
    return ["bwrap", "--ro-bind", "/", "/", "--tmpfs", "/tmp", "--bind", w, w, "--chdir", w,
            "--dev", "/dev", "--proc", "/proc", "--unshare-all", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL", "--setenv", "HOME", w]

def run(cmd, workdir, timeout=None, _probe=False):
    """Run `cmd` with sh inside the jail, traced. Raises JailUnavailable
    rather than ever running it any other way."""
    if shutil.which("bwrap") is None or shutil.which("strace") is None:
        raise JailUnavailable("bwrap and strace are both required; not running the command")
    timeout = TIMEOUT if timeout is None else timeout
    tdir = tempfile.mkdtemp(prefix="jailtrace_"); trace = os.path.join(tdir, "t")
    # -ff: one file per process, so no call is split across interleaved lines
    # -y: every fd is printed with the path it names - the directory a call is
    # relative to, and the file an open actually reached (symlinks resolved)
    argv = ["strace", "-ff", "-qq", "-y", "--decode-pids=pidns", "-s", "4096", "-e", f"trace={SYSCALLS}", "-o", trace,
            *_bwrap(workdir), "sh", "-c", cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        rc, out, err, to = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = -9, e.stdout or "", e.stderr or "", True
        out = out.decode() if isinstance(out, bytes) else out
        err = err.decode() if isinstance(err, bytes) else err
    try:
        per_pid = {int(f.rsplit(".", 1)[1]): open(os.path.join(tdir, f)).read()
                   for f in os.listdir(tdir) if f.startswith("t.")}
    finally: shutil.rmtree(tdir, ignore_errors=True)
    events = parse(per_pid, cmd)
    if not _probe and events is None:
        raise JailUnavailable("the trace never shows the command starting; not trusting an unobserved run")
    return Execution(rc, out, err, events or [], to)

_LINE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')

def _unescape(s): return bytes(s, "utf-8").decode("unicode_escape", errors="replace")

_DIRFD = re.compile(r"(?:AT_FDCWD|\d+)<([^>]*)>")
_RESOLVED = re.compile(r"^<([^>]*)>")

def _where(args, name, ret_rest, ok, nth=0):
    """The path a call really touched. A successful open reports the file it
    reached (-y), which settles symlinks and relative paths; otherwise the
    name is joined to the directory the call was relative to."""
    if ok:
        m = _RESOLVED.match(ret_rest.strip())
        if m: return m.group(1)
    if name.startswith("/"): return name
    dirs = _DIRFD.findall(args)
    return os.path.join(dirs[nth], name) if len(dirs) > nth else name

def _calls(text):
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m: yield m.groups()

def parse(per_pid, cmd):
    """{pid: that process's strace output} -> [(kind, detail, succeeded)], or
    None if no process ever became `sh -c cmd`. Only that process (from the
    moment it did) and its descendants count: before it, the same process was
    bubblewrap setting up the jail, which is not the plan's doing."""
    root = None
    for pid, text in per_pid.items():
        for call, args, ret, _ in _calls(text):
            if call == "execve" and ret == "0":
                argv = [_unescape(x) for x in _STR.findall(args)][1:]
                if argv[:2] == ["sh", "-c"] and argv[2:3] == [cmd]: root = pid
    if root is None: return None
    events, frontier, seen = [], [(root, True)], set()
    while frontier:
        pid, wait_for_exec = frontier.pop(0)
        if pid in seen or pid not in per_pid: continue
        seen.add(pid); started = not wait_for_exec
        for call, args, ret, rest in _calls(per_pid[pid]):
            ok = ret != "?" and not ret.startswith("-")
            strs = [_unescape(x) for x in _STR.findall(args)]
            if not started:
                if call == "execve" and ok and strs[1:3] == ["sh", "-c"]: started = True
                continue
            if call in ("clone", "clone3", "fork", "vfork"):
                # Inside the jail's PID namespace the return value is the
                # child's namespace pid; the trace files are named by host
                # pid, which --decode-pids=pidns appends as a comment.
                host = re.search(r"/\* (\d+) in strace's PID NS \*/", rest)
                if ok and host: frontier.append((int(host.group(1)), False))
            elif call == "execve":
                argv = tuple(strs[1:] if len(strs) > 1 else strs)
                if ok: events.append(("exec", argv, ok))
            elif call in ("openat", "open", "creat"):
                if strs:
                    write = call == "creat" or any(f in args for f in WRITE_FLAGS)
                    events.append(("write" if write else "read", _where(args, strs[0], rest, ok), ok))
            elif call == "connect":
                if "AF_UNIX" in args: continue             # local sockets are not the network
                ip = re.search(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', args)
                events.append(("connect", (ip.group(1) or ip.group(2)) if ip else args[:80], ok))
            elif call in ("unlinkat", "unlink"):
                if strs: events.append(("unlink", _where(args, strs[-1], "", False), ok))
            elif call in ("renameat", "renameat2", "rename"):
                if len(strs) >= 2:
                    events.append(("rename", (_where(args, strs[0], "", False, 0),
                                              _where(args, strs[1], "", False, 1)), ok))
            elif call == "kill":
                events.append(("kill", args.split(",")[0].strip(), ok))
    return events

def effects_of(events, workdir):
    """What the trace shows the command did or tried to do, as Vow effects."""
    effects = {"exec"}
    for kind, detail, ok in events:
        if kind == "exec":
            name = os.path.basename(detail[0]) if detail else "?"
            if name not in VETTED_COMMANDS: effects.add("exec_unvetted")
            line = " ".join(detail)
            if DESTRUCT_CMDS.search(line): effects.add("destruct")
            if DOMINATE_CMDS.search(line): effects.add("dominate")
            if name in NETWORK_COMMANDS:
                effects.add("network_access")
                for a in detail[1:]:
                    if not a.startswith("-") and ("://" in a or "." in a): _touch_host(a, effects)
            if name in PACKAGE_COMMANDS: effects.update({"network_access", "network_unlisted"})
            if name in FILE_READERS:        # what the command was asked to read, by name
                ops = [a for a in detail[1:] if not a.startswith("-")]
                for f in (ops[1:] if name == "grep" else ops): _touch_path(f, workdir, effects, write=False)
        elif kind == "read":
            p = normalise(detail, workdir)
            if not inside(p, workdir) and p.startswith(LOADER_READS): continue
            # /proc/self resolves to /proc/<pid>: inside the jail's own PID
            # namespace that shows only the jail's processes. /proc/sys and
            # the rest of /proc stay visible as reads outside the workdir.
            if re.match(r"^/proc/\d+/", p): continue
            _touch_path(detail, workdir, effects, write=False)
        elif kind == "write":
            _touch_path(detail, workdir, effects, write=True)
        elif kind == "unlink":
            _touch_path(detail, workdir, effects, write=True)
        elif kind == "rename":
            for path in detail: _touch_path(path, workdir, effects, write=True)
        elif kind == "connect":
            effects.update({"network_access", "network_unlisted"})
        elif kind == "kill":
            if detail.startswith("-"): effects.add("dominate")   # a whole process group, or everyone
    return effects
