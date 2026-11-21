"""Landlock on the gate (P1): the process that parses everything untrusted
cannot open the workdir at all (docs/monitor-boundary.md, section 3, P1;
Phase 2, slice 3b).

The gate reaches the workdir only through its monitor process (monitor.py),
which runs every real call, rehearsal and replay, and holds the workdir's
descriptor and the key. Once the monitors are started, guarded_agent's
command line restricts its own process with Landlock to what it still needs:

  read and execute   the system directories, Python's installation and
                     import path, this repository, the Lean and Coq toolchains
  read               the certificates TLS trusts, where they are named
                     (SSL_CERT_FILE, a proxy's CA bundle) or found (certifi)
  read               the anthropic SDK's stored login (`ant auth login`), when
                     it is the backend and no key in the environment comes
                     first; in its credentials directory the gate may also
                     replace a file, as refreshing a token does
  everything         its own scratch directory, which becomes TMPDIR
  read and write     /dev's device files (/dev/null), and the ledger and
                     run-records files, which exist before it restricts itself

Landlock grants, it cannot subtract, so the workdir is simply not among them:
a workdir inside any of these paths, or holding one of them, is refused
before anything is restricted.

It then gives up every capability (Phase 3, slice 3). Under Landlock the gate
is refused ptrace, and the calls checked like it, on any process outside its
domain: its monitors and co-signers, started before it confined itself. A
capability reaches their memory by other ways, though: a gate running as
root could still sample their stacks with perf. With no_new_privs set, as
Landlock requires, no program it runs gets a capability back.

Afterwards the gate checks that it really cannot open the workdir, that it
holds no descriptor into it (Landlock does not revoke a descriptor already
open), and that it holds no capability. Any of these failing is a refusal.

A process under Landlock cannot mount anything, so it could not start a jail:
everything that does runs in a monitor process, started before this.
"""
import os
import shutil
import sys
import tempfile

import confine as C

# Landlock filesystem rights (include/uapi/linux/landlock.h)
EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_FILE, MAKE_REG = 1 << 5, 1 << 8
TRUNCATE, IOCTL_DEV = 1 << 14, 1 << 15
READ_EXEC = EXECUTE | READ_FILE | READ_DIR
# The rights a rule on a file (not a directory) may carry.
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
EVERYTHING = (1 << 16) - 1
# Replacing a file in a directory the way the SDK does: a temporary file made
# beside it (MAKE_REG, WRITE_FILE), renamed over it (REMOVE_FILE).
REPLACE = WRITE_FILE | MAKE_REG | REMOVE_FILE
# The rights that change what is there.
WRITES = WRITE_FILE | MAKE_REG | REMOVE_FILE | TRUNCATE
# Capabilities (include/uapi/linux/prctl.h, capability.h)
PR_CAPBSET_DROP, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 24, 47, 4
CAPABILITY_VERSION_3 = 0x20080522

SYSTEM = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/proc", "/sys")
TOOLS = ("lean", "coqc")
# Where TLS finds the certificates it trusts, when they are named rather than
# left at OpenSSL's defaults (a proxy's CA bundle, say): read, file by file.
CA_FILES = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
CA_DIRS = ("SSL_CERT_DIR",)


def trust_stores():
    """(files, directories) the process's TLS reads its trusted certificates from."""
    import ssl
    files = {os.environ[v] for v in CA_FILES if os.environ.get(v)}
    dirs = {os.environ[v] for v in CA_DIRS if os.environ.get(v)}
    paths = ssl.get_default_verify_paths()
    files |= {p for p in (paths.cafile, paths.openssl_cafile) if p}
    dirs |= {p for p in (paths.capath, paths.openssl_capath) if p}
    try:
        import certifi
        files.add(certifi.where())
    except ImportError:
        pass
    return sorted(f for f in files if os.path.isfile(f)), sorted(d for d in dirs if os.path.isdir(d))


def sdk_config_dir():
    """Where the anthropic SDK keeps the login `ant auth login` stores: the
    SDK's own rule (anthropic/lib/credentials/_constants.py, _config_dir),
    which tests/test_gate_landlock.py holds this to."""
    return os.environ.get("ANTHROPIC_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "anthropic")


def stored_login():
    """(directories read, directories a file is replaced in, files read): what
    the anthropic SDK reads and writes of its stored login. It reads the
    profile's config when the client is made and its credentials at every
    token fetch; refreshing the token, it replaces the credentials file. A
    workload identity token named by ANTHROPIC_IDENTITY_TOKEN_FILE is re-read
    at every exchange. Nothing when ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN
    is set, as the SDK then reads none of it."""
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return [], [], []
    base = sdk_config_dir()
    creds = os.path.join(base, "credentials")
    token = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
    return ([base] if os.path.isdir(base) else [], [creds] if os.path.isdir(creds) else [],
            [token] if token and os.path.isfile(token) else [])


class Refused(C.Refused):
    """The gate must not start: it cannot be confined as it should be."""

class Unavailable(Refused):
    """This kernel has no Landlock: the gate runs unconfined, and says so."""


def _within(a, b):
    return a == b or a.startswith(b.rstrip("/") + "/")


def plan(scratch, files=(), anthropic=False):
    """[(path, rights)]: everything the confined gate may still reach.
    anthropic: the model is called through the anthropic SDK."""
    here = os.path.dirname(os.path.abspath(__file__))
    roots = set(SYSTEM) | {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, here}
    roots |= {p for p in sys.path if p and os.path.isdir(p)}
    for tool in TOOLS:
        found = shutil.which(tool)
        if found:     # <toolchain>/bin/<tool>: the toolchain's libraries are beside its bin
            roots.add(os.path.dirname(os.path.dirname(os.path.realpath(found))))
    rules = [(r, READ_EXEC) for r in sorted(roots) if os.path.isdir(r)]
    ca_files, ca_dirs = trust_stores()
    rules += [(f, READ_FILE) for f in ca_files] + [(d, READ_FILE | READ_DIR) for d in ca_dirs]
    if anthropic:
        read, replace, tokens = stored_login()
        rules += [(d, READ_FILE | READ_DIR) for d in read] + [(d, READ_FILE | READ_DIR | REPLACE) for d in replace]
        rules += [(f, READ_FILE) for f in tokens]
    rules.append(("/dev", READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV))
    rules.append((scratch, EVERYTHING))
    rules += [(f, READ_FILE | WRITE_FILE | TRUNCATE) for f in files]
    return rules


def conflicts(workdir, rules):
    """The granted paths that hold the workdir or lie inside it."""
    w = os.path.realpath(workdir)
    return sorted({p for p in (os.path.realpath(path) for path, _ in rules)
                   if _within(w, p) or _within(p, w)})


def threads():
    with open("/proc/self/status") as f:
        return next(int(line.split()[1]) for line in f if line.startswith("Threads:"))

def capabilities():
    """This process's capability sets, {"CapEff": bits, ...}, from /proc/self/status."""
    with open("/proc/self/status") as f:
        return {k: int(v, 16) for k, v in (line.split(":") for line in f if line.startswith("Cap"))}

def drop_capabilities(libc):
    """Give up every capability, for good: the ambient set, the bounding set,
    and the effective, permitted and inheritable sets. The bounding set takes
    CAP_SETPCAP to change; a process without it holds no capability it could
    use, and no_new_privs keeps any program it runs from gaining one."""
    import ctypes
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    try:
        with open("/proc/sys/kernel/cap_last_cap") as f: last = int(f.read())
    except (OSError, ValueError):
        last = 63
    if capabilities().get("CapEff", 0) >> 8 & 1:          # CAP_SETPCAP
        for cap in range(last + 1):
            if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0: C._fail(f"prctl(PR_CAPBSET_DROP, {cap})")
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
    if libc.capset(ctypes.byref(Header(CAPABILITY_VERSION_3, 0)), (Data * 2)()) != 0: C._fail("capset")

def check(workdir):
    """Refused unless this process can neither open the workdir nor holds a
    descriptor into it, and holds no capability."""
    held = {k: f"{v:x}" for k, v in capabilities().items() if k != "CapBnd" and v}
    if held: raise Refused(f"the gate still holds capabilities: {held}")
    w = os.path.realpath(workdir)
    try:
        fd = os.open(w, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except PermissionError:
        pass
    else:
        os.close(fd)
        raise Refused(f"the gate can still open the workdir {w}")
    for name in os.listdir("/proc/self/fd"):
        try: target = os.readlink(f"/proc/self/fd/{name}")
        except OSError: continue
        if _within(target, w):
            raise Refused(f"the gate holds a descriptor into the workdir: {name} -> {target}")


# Removing the scratch directory takes write access to its parent, which the
# confined gate does not have. So a reaper, started before the gate restricts
# itself, waits for the gate's end of a pipe to close (however the gate ends)
# and then removes that one directory. It is given the path and nothing else.
REAPER = "import shutil, sys; sys.stdin.buffer.read(); shutil.rmtree(sys.argv[1], ignore_errors=True)"
_reapers = []      # the pipe's write end stays open for as long as this process lives

def _reaper(scratch):
    import subprocess
    try:
        p = subprocess.Popen([sys.executable, "-I", "-c", REAPER, scratch], stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        _reapers.append(p)
    except OSError:
        pass                          # then the directory outlives the gate, as any temporary file can


def _restrict(libc, abi, rules):
    import ctypes
    if libc.prctl(C.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        C._fail("prctl(PR_SET_NO_NEW_PRIVS)")
    handled = C.handled_access(abi)
    attr = C._RulesetAttr(handled)
    rfd = libc.syscall(C.SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0: C._fail("landlock_create_ruleset")
    try:
        for path, rights in rules:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                mask = handled if os.path.isdir(path) else handled & FILE_RIGHTS
                rule = C._PathBeneath(rights & mask, fd)
                if libc.syscall(C.SYS_LANDLOCK_ADD_RULE, rfd, C.LANDLOCK_RULE_PATH_BENEATH,
                                ctypes.byref(rule), 0) < 0:
                    C._fail(f"landlock_add_rule {path}")
            finally:
                os.close(fd)
        if libc.syscall(C.SYS_LANDLOCK_RESTRICT_SELF, rfd, 0) < 0:
            C._fail("landlock_restrict_self")
    finally:
        os.close(rfd)


def restrict(rules):
    """Restrict this process for good to `rules`, [(path, rights)], and
    nothing else: what the monitor does to itself when it is captured
    (monitor.capture). Unavailable if this kernel has no Landlock."""
    libc = C._libc()
    abi = libc.syscall(C.SYS_LANDLOCK_CREATE_RULESET, None, 0, C.LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 1: raise Unavailable("this kernel has no Landlock")
    try: _restrict(libc, abi, rules)
    except C.Refused as e:
        raise e if isinstance(e, Refused) else Refused(str(e)) from None


def confine_gate(workdir, files=(), anthropic=False, private=()):
    """Restrict this process for good. Returns its scratch directory, now TMPDIR.
    private: directories that are another process's to write (the monitor's
    quarantine stream): refused if the gate could write them."""
    for f in files:
        if not os.path.isfile(f): raise Refused(f"{f} must exist before the gate is confined")
    scratch = tempfile.mkdtemp(prefix="gate_")
    rules = plan(scratch, files, anthropic)
    bad = conflicts(workdir, rules)
    if bad:
        shutil.rmtree(scratch, ignore_errors=True)
        raise Refused(f"the workdir {os.path.realpath(workdir)} overlaps {bad[0]}, which the gate must keep "
                      f"reaching; choose a workdir outside it")
    for path in private:
        hit = conflicts(path, [(p, r) for p, r in rules if r & WRITES])
        if hit:
            shutil.rmtree(scratch, ignore_errors=True)
            raise Refused(f"{os.path.realpath(path)} overlaps {hit[0]}, which the gate may write; "
                          f"choose a directory outside it")
    libc = C._libc()
    abi = libc.syscall(C.SYS_LANDLOCK_CREATE_RULESET, None, 0, C.LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 1:
        shutil.rmtree(scratch, ignore_errors=True)
        raise Unavailable("this kernel has no Landlock")
    if threads() != 1:          # Landlock and capabilities are a thread's: another would keep both
        shutil.rmtree(scratch, ignore_errors=True)
        raise Refused(f"the gate has {threads()} threads; it is confined only while it has one")
    _reaper(scratch)
    try:
        _restrict(libc, abi, rules)
        drop_capabilities(libc)
    except C.Refused as e:
        raise e if isinstance(e, Refused) else Refused(str(e)) from None
    os.environ["TMPDIR"] = scratch
    tempfile.tempdir = scratch
    check(workdir)
    return scratch
