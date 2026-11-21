
# Real execution, observed. The critic judges a plan from a dry run, which
# cannot see what a command does once it runs: a script's contents, a
# command inside $(...), a symlink, behaviour that differs at run time. This
# runs an approved shell command for real, inside a jail, under strace, and
# turns what the trace shows into effects in the same vocabulary the Vow uses.
#
#   prevention   bubblewrap: only the system directories and a short list of
#                /etc's files, read-only (no home directories, no /run where
#                the host's daemons listen, no /var); the workdir the only
#                writable path; a fresh /tmp; no network; its own process and
#                IPC namespaces (kill -9 -1 reaches nothing outside); no new
#                privileges; killed with its parent
#                confine.py, inside it: Landlock lets the command read only
#                the system directories and write only the workdir, whatever
#                call it opens a file with; seccomp refuses the calls that
#                open or execute a file out of strace's sight (openat2,
#                execveat, io_uring, file handles), so the trace is complete,
#                and refuses Unix sockets, so a socket file the binds missed
#                stays out of reach
#   detection    strace -f: every exec, open, connect, unlink, rename and
#                kill, including the ones the jail refused. A connect to a
#                Unix socket file is judged as a write to that path. An attempt is
#                an effect: trying to write /etc is the harm the Vow names,
#                whether or not the jail let it land.
#                The calls confine.py's filter refuses are traced too, so an
#                attempt at one is in the record as a "refused" event. That is
#                telemetry, not an effect (docs/monitor-boundary.md, section 5):
#                glibc's name lookups try socket(AF_UNIX) in ordinary commands.
#                strace must not use --seccomp-bpf, which would hide them
#                (tests/test_refused_calls.py).
#
# Fail closed: without bwrap and strace nothing runs, and neither does a
# command confine.py could not confine. Never "run it unjailed".
import os, re, shutil, subprocess, tempfile
from dataclasses import dataclass, field

import policy as policy_mod
from observation import (FILE_READERS, NETWORK_COMMANDS, PACKAGE_COMMANDS,
                         DESTRUCT_CMDS, DOMINATE_CMDS, _touch_host, _touch_path, inside, normalise)

TIMEOUT = 30.0
CONFINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confine.py")
# The calls confine.py's filter refuses (its SYSCALL_TABLES), traced so that an
# attempt at one is recorded; tests/test_refused_calls.py keeps the two in step.
# The value is where the call's path argument is, or None if it has none.
REFUSABLE = {"openat2": 1, "execveat": 1, "name_to_handle_at": 1, "open_by_handle_at": None,
             "io_uring_setup": None, "io_uring_enter": None, "io_uring_register": None,
             "socket": None}
SYSCALLS = ("execve,openat,open,creat,connect,unlinkat,unlink,renameat,renameat2,rename,kill,"
            "clone,clone3,fork,vfork," + ",".join(REFUSABLE))
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
# glibc asks nscd before it reads /etc/passwd: libc's doing, as LOADER_READS.
LIBC_SOCKETS = ("/run/nscd/socket", "/var/run/nscd/socket")

# What of the host the jail sees, all of it read-only. The system directories
# (a merged-/usr symlink is recreated as a symlink), and from /etc only what
# programs read to start, to name owners and hosts, to find their alternatives
# and their locale. Not /etc itself: a jail started as root could read
# /etc/shadow and the host's SSH keys there.
SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
ETC = ("ld.so.cache", "ld.so.conf", "ld.so.conf.d",                     # the loader
       "nsswitch.conf", "passwd", "group", "hosts", "host.conf",        # names
       "gai.conf", "resolv.conf", "protocols", "services", "networks",
       "localtime", "timezone", "locale.alias", "locale.conf",          # time, locale
       "alternatives", "terminfo", "mime.types", "magic", "magic.mime",  # programs
       "ssl/certs", "os-release", "lsb-release", "debian_version", "hostname")

def _etc_entries():
    # Debian's Pythons keep sitecustomize under /etc/python3.X.
    extra = sorted(e for e in os.listdir("/etc") if re.fullmatch(r"python3(\.\d+)?", e))
    return list(ETC) + extra

def _system_binds():
    out = []
    for d in SYSTEM_DIRS:
        if os.path.islink(d): out += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d): out += ["--ro-bind", d, d]
    for e in _etc_entries():
        out += ["--ro-bind-try", "/etc/" + e, "/etc/" + e]
    return out

class JailUnavailable(Exception): pass

@dataclass
class Execution:
    returncode: int; stdout: str; stderr: str
    events: list = field(default_factory=list)      # (kind, detail, succeeded)
    trace: dict = field(default_factory=dict)       # {pid: raw strace text}, for an independent reading
    timed_out: bool = False

def available():
    """(True, "") when a jailed, traced run works on this machine, else (False, why)."""
    for tool in ("bwrap", "strace"):
        if shutil.which(tool) is None: return False, f"{tool} not installed"
    try:
        with tempfile.TemporaryDirectory() as d:
            r = run("true", d, _probe=True)
        if r.returncode != 0:
            why = f"jail probe exited {r.returncode}: {r.stderr.strip()[-200:]}"
            if "Operation not permitted" in r.stderr:
                # Ubuntu 23.10+ lets unprivileged users create a user namespace
                # but strips its capabilities through AppArmor, so bwrap cannot
                # even bring up loopback (seen on GitHub's ubuntu-24.04 runners).
                why += (" - unprivileged user namespaces look restricted; allow them "
                        "(sysctl kernel.apparmor_restrict_unprivileged_userns=0) or give "
                        "bwrap an AppArmor profile that permits userns")
            return False, why
    except (JailUnavailable, OSError, subprocess.SubprocessError) as e:
        return False, f"jail probe failed: {e}"
    return True, ""

def _bwrap(workdir, source=None):
    # source: mount this directory at the workdir's path instead (a co-signer
    # replaying a run against its own snapshot, where the command sees the
    # same paths it saw the first time)
    w = os.path.realpath(workdir)
    s = os.path.realpath(source) if source else w
    return ["bwrap", *_system_binds(), "--tmpfs", "/tmp", "--bind", s, w, "--chdir", w,
            "--dev", "/dev", "--proc", "/proc", "--unshare-all", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL",
            # A clean environment: the host's may hold tokens, and its loader
            # variables (LD_LIBRARY_PATH on GitHub's runners) change what every
            # program opens. Only these three go in.
            "--clearenv", "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--setenv", "HOME", w, "--setenv", "LANG", "C.UTF-8"] + _confine(w)

def _confine(w):
    # Run by the jail's own python3 (found on the PATH above), not the one
    # running the guard: that one may live outside the system directories
    # and need loader variables the jail does not pass in. The source goes in
    # with -c rather than as a path, because this repository may itself be
    # where the jail cannot see it (anywhere under /tmp, which is the jail's own).
    with open(CONFINE) as f: source = f.read()
    return ["python3", "-I", "-c", source, w, "--"]

def run(cmd, workdir, timeout=None, _probe=False, source=None):
    """Run `cmd` with sh inside the jail, traced. Raises JailUnavailable
    rather than ever running it any other way. source: a directory to mount at
    the workdir's path in its place (a rehearsal's copy, see _bwrap)."""
    rc, out, err, per_pid, to = run_raw(cmd, workdir, timeout, source)
    events = parse(per_pid, cmd)
    if not _probe and events is None:
        refused = [l for l in err.splitlines() if l.startswith("dharma-jail:")]
        if refused: raise JailUnavailable(refused[-1])
        raise JailUnavailable("the trace never shows the command starting; not trusting an unobserved run")
    return Execution(rc, out, err, events or [], trace=per_pid, timed_out=to)

def run_raw(cmd, workdir, timeout=None, source=None):
    """Run `cmd` in the jail and return (returncode, stdout, stderr, {pid:
    raw trace}, timed_out) without reading the trace: the monitor runs
    commands this way and parses nothing (monitor.py); the gate parses."""
    if shutil.which("bwrap") is None or shutil.which("strace") is None:
        raise JailUnavailable("bwrap and strace are both required; not running the command")
    timeout = TIMEOUT if timeout is None else timeout
    tdir = tempfile.mkdtemp(prefix="jailtrace_"); trace = os.path.join(tdir, "t")
    # -ff: one file per process, so no call is split across interleaved lines
    # -y: every fd is printed with the path it names - the directory a call is
    # relative to, and the file an open actually reached (symlinks resolved)
    argv = ["strace", "-ff", "-qq", "-y", "--decode-pids=pidns", "-s", "4096", "-e", f"trace={SYSCALLS}", "-o", trace,
            *_bwrap(workdir, source=source), "sh", "-c", cmd]
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
    return rc, out, err, per_pid, to

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
    dirs = _DIRFD.findall(args)
    path = name if name.startswith("/") else (os.path.join(dirs[nth], name) if len(dirs) > nth else name)
    # A failed open reports no file. Resolve what can be resolved after the
    # run: a symlink the command left in the workdir (ln -s /etc outside) is
    # still there, and / is the same inside the jail as out.
    return os.path.realpath(path) if path.startswith("/") else path

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
                if "AF_UNIX" in args:
                    # A socket file is a path, and connecting to it delivers
                    # bytes to whatever listens there. An abstract name (@...)
                    # lives in the jail's own network namespace.
                    m = re.search(r'sun_path=("(?:[^"\\]|\\.)*")', args)
                    if m:
                        p = _unescape(m.group(1)[1:-1])
                        events.append(("unix", os.path.realpath(p) if p.startswith("/") else p, ok))
                    continue
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
            elif call in REFUSABLE:
                # Recorded only when it failed: a socket the filter allows is
                # no event (its connect is). (call, what it named, errno).
                if ok or not ret.startswith("-"): continue
                at = REFUSABLE[call]
                if call == "socket": what = args.split(",")[0].strip()
                elif at is not None and len(strs) > 0: what = _where(args, strs[0], "", False)
                else: what = ""
                err = re.match(r"\s*(E[A-Z0-9]+)", rest)
                events.append(("refused", (call, what, err.group(1) if err else ""), False))
    return events

def effects_of(events, workdir, policy=None):
    """What the trace shows the command did or tried to do, as Vow effects,
    under `policy` (policy.py; None for the default)."""
    pol = policy_mod.of(policy)
    effects = {"exec"}
    for kind, detail, ok in events:
        if kind == "exec":
            name = os.path.basename(detail[0]) if detail else "?"
            if name not in pol.vetted_commands: effects.add("exec_unvetted")
            line = " ".join(detail)
            if DESTRUCT_CMDS.search(line): effects.add("destruct")
            if DOMINATE_CMDS.search(line): effects.add("dominate")
            if name in NETWORK_COMMANDS:
                effects.add("network_access")
                for a in detail[1:]:
                    if not a.startswith("-") and ("://" in a or "." in a): _touch_host(a, effects, pol)
            if name in PACKAGE_COMMANDS: effects.update({"network_access", "network_unlisted"})
            if name in FILE_READERS:        # what the command was asked to read, by name
                ops = [a for a in detail[1:] if not a.startswith("-")]
                for f in (ops[1:] if name == "grep" else ops): _touch_path(f, workdir, effects, False, pol)
        elif kind == "read":
            p = normalise(detail, workdir)
            if not inside(p, workdir) and p.startswith(LOADER_READS): continue
            # /proc/self resolves to /proc/<pid>: inside the jail's own PID
            # namespace that shows only the jail's processes. /proc/sys and
            # the rest of /proc stay visible as reads outside the workdir.
            if re.match(r"^/proc/\d+/", p): continue
            _touch_path(detail, workdir, effects, False, pol)
        elif kind == "write":
            _touch_path(detail, workdir, effects, True, pol)
        elif kind == "unlink":
            _touch_path(detail, workdir, effects, True, pol)
        elif kind == "rename":
            for path in detail: _touch_path(path, workdir, effects, True, pol)
        elif kind == "connect":
            effects.update({"network_access", "network_unlisted"})
        elif kind == "unix":
            # Judged as a write to the socket's path: outside the workdir it is
            # write_outside_workdir, whatever listens there. A relative path
            # resolves against a working directory the trace does not show, so
            # it is taken to be outside.
            if detail in LIBC_SOCKETS: continue
            if not detail.startswith("/"): effects.update({"write", "write_outside_workdir"}); continue
            _touch_path(detail, workdir, effects, True, pol)
        elif kind == "kill":
            if detail.startswith("-"): effects.add("dominate")   # a whole process group, or everyone
        elif kind == "refused":
            continue    # telemetry: an attempt the filter stopped, recorded and never judged
    return effects
