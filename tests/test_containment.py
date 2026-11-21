"""What the jail contains, probed so that breaking the jail is safe.

Each probe checks one containment property against something the test owns:
a sibling directory it made, a sentinel process it started, a socket it is
listening on, an environment variable it set. So the probes can run against a
deliberately broken jail (containment_mutants.py does exactly that, one
bubblewrap flag or one part of confine.py at a time) without anything real
being written, read, killed or reached. A probe that sees the jail fail says ESCAPE:, which is how the
mutation runner tells a probe that caught a break from a jail that merely
failed to start."""
import os, pathlib, shutil, socket, subprocess, sys, tempfile, time, uuid

import pytest

import tests.support  # noqa: F401
import jail
from tests.test_jail import needs_jail

pytestmark = needs_jail

@pytest.fixture
def work(tmp_path):
    w = tmp_path / "work"; w.mkdir()
    return w

def run(cmd, work, **kw):
    return jail.run(cmd, str(work), **kw)

@pytest.fixture
def sentinel():
    """A process outside the jail, owned by the same user."""
    p = subprocess.Popen(["sleep", "300"])
    yield p
    p.kill(); p.wait()

def test_only_the_workdir_is_writable(work, tmp_path):
    """A directory the test user can write, next to the workdir: the root is
    read-only in the jail and only the workdir is bound writable."""
    outside = tmp_path / "outside"; outside.mkdir()
    run(f"echo x > {outside}/escape; echo x > inside", work)
    assert (work / "inside").exists(), "the jail could not write its own workdir"
    assert not (outside / "escape").exists(), "ESCAPE: wrote outside the workdir"

def test_the_host_filesystem_is_read_only(work):
    """The sibling above is under /tmp, which the jail replaces with its own:
    it proves only that the workdir's neighbours are not bound. This one is a
    directory the test user can write outside /tmp (in its home), which only
    a read-only root keeps the jail from."""
    home = pathlib.Path.home()
    assert not str(home.resolve()).startswith("/tmp"), "the probe needs a writable directory outside /tmp"
    outside = pathlib.Path(tempfile.mkdtemp(prefix=".dharma-containment-", dir=home))
    try:
        run(f"echo x > {outside}/escape", work)
        assert not (outside / "escape").exists(), "ESCAPE: wrote to the host filesystem"
    finally: shutil.rmtree(outside, ignore_errors=True)

def test_tmp_is_the_jails_own(work):
    marker = f"/tmp/dharma-{uuid.uuid4().hex}"
    run(f"echo x > {marker} && cat {marker} > seen", work)
    assert not os.path.exists(marker), "ESCAPE: the jail's /tmp is the host's"

def test_there_is_no_network(work):
    """A listener on the host's loopback. In its own network namespace the
    jail has a loopback of its own and cannot reach this one."""
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); srv.settimeout(0.5)
    port = srv.getsockname()[1]
    try:
        run(f"python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=2)\"", work)
        try: conn, _ = srv.accept()
        except socket.timeout: conn = None
        assert conn is None, "ESCAPE: reached the host's network"
    finally: srv.close()

def test_host_processes_cannot_be_signalled(work, sentinel):
    run(f"kill -TERM {sentinel.pid}", work)
    time.sleep(0.2)
    assert sentinel.poll() is None, "ESCAPE: signalled a process outside the jail"

def test_host_processes_cannot_be_seen(work, sentinel):
    run(f"test -e /proc/{sentinel.pid}/cmdline && cat /proc/{sentinel.pid}/cmdline > seen; true", work)
    assert not (work / "seen").exists(), "ESCAPE: saw a process outside the jail"

def test_host_devices_are_not_there(work):
    """The jail gets a minimal /dev of its own, not the host's disks and consoles."""
    run("ls /dev > devs", work)
    devs = set((work / "devs").read_text().split())
    assert "null" in devs, "the jail has no /dev at all"
    extra = devs - {"core", "fd", "full", "null", "ptmx", "pts", "random", "shm", "stderr",
                    "stdin", "stdout", "tty", "urandom", "zero", "mqueue", "console"}
    assert not extra, f"ESCAPE: host devices visible in the jail: {sorted(extra)[:8]}"

def test_the_host_environment_is_not_inherited(work, monkeypatch):
    monkeypatch.setenv("DHARMA_CONTAINMENT_SECRET", "s3cret")
    run('echo "[$DHARMA_CONTAINMENT_SECRET]" > env.txt', work)
    assert (work / "env.txt").read_text() == "[]\n", "ESCAPE: the host's environment reached the jail"

def test_no_capabilities(work):
    run("grep -E '^Cap(Eff|Prm|Bnd|Amb):' /proc/self/status > caps", work)
    caps = dict(l.split(":") for l in (work / "caps").read_text().splitlines())
    held = {k: v.strip() for k, v in caps.items() if int(v, 16)}
    assert len(caps) == 4, "could not read the jail's capabilities"
    assert not held, f"ESCAPE: the jail holds capabilities {held}"

def _alive(marker):
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try: cmd = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError: continue
        if marker.encode() in cmd: yield int(pid)

def test_nothing_outlives_a_stopped_run(work):
    """A run that is stopped (it timed out) takes everything it started with it."""
    marker = f"{300 + uuid.uuid4().int % 1000}.{uuid.uuid4().int % 1000}"
    try:
        r = run(f"sleep {marker} & sleep {marker}", work, timeout=2)
        assert r.timed_out
        time.sleep(0.5)
        left = list(_alive(f"sleep\x00{marker}"))
        assert not left, f"ESCAPE: {len(left)} process(es) from the jail outlived it"
    finally:
        for pid in _alive(f"sleep\x00{marker}"):
            try: os.kill(pid, 9)
            except OSError: pass

def _outside_tmp():
    """A directory of the test's own outside /tmp (the jail has its own /tmp)."""
    home = pathlib.Path.home()
    assert not str(home.resolve()).startswith("/tmp"), "the probe needs a directory outside /tmp"
    return pathlib.Path(tempfile.mkdtemp(prefix=".dharma-containment-", dir=home))

def test_only_the_system_directories_are_readable(work):
    """A file only the test user can read, in its home, as credentials are.
    The read-only root shows it to the jail; only confine.py's Landlock ruleset
    keeps the command from reading it."""
    outside = _outside_tmp()
    try:
        secret = outside / "credentials"
        secret.write_text("dharma-containment-dummy\n"); secret.chmod(0o600)
        run(f"cat {secret} > seen; echo ran >> seen", work)
        seen = (work / "seen").read_text()
        assert "ran" in seen, "the command did not run"
        assert "dharma-containment-dummy" not in seen, "ESCAPE: read a file outside the system directories"
    finally: shutil.rmtree(outside, ignore_errors=True)

UNTRACED = """import ctypes, errno, platform
L = ctypes.CDLL(None, use_errno=True); L.syscall.restype = ctypes.c_long
openat2, execveat = {"x86_64": (437, 322), "aarch64": (437, 281)}[platform.machine()]
class How(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
def call(nr, *args):
    r = L.syscall(nr, *args)
    return "ok" if r >= 0 else errno.errorcode.get(ctypes.get_errno(), "?")
seen = {"openat2": call(openat2, -100, b"target", ctypes.byref(How()), 24),
        "execveat": call(execveat, -100, b"./no-such-program", None, None, 0),
        "io_uring_setup": call(425, 1, ctypes.byref((ctypes.c_char * 120)()))}
open("calls", "w").write("\\n".join(f"{k} {v}" for k, v in seen.items()))
"""

def test_calls_the_trace_cannot_see_are_refused(work):
    """Calls that open or execute a file without a call strace traces. Each
    must be refused before it reaches the kernel (ENOSYS, from confine.py's
    filter), so a program falls back to a call the trace shows. openat2 is
    aimed at a file in the workdir, which Landlock allows, so only the filter
    can stop it; anything other than ENOSYS means the call reached the kernel."""
    (work / "target").write_text("x")
    (work / "probe.py").write_text(UNTRACED)
    run("python3 probe.py", work)
    calls = dict(l.split(" ", 1) for l in (work / "calls").read_text().splitlines())
    assert set(calls) == {"openat2", "execveat", "io_uring_setup"}, "the probe did not run"
    reached = {k: v for k, v in calls.items() if v != "ENOSYS"}
    assert not reached, f"ESCAPE: calls the trace cannot see reached the kernel: {reached}"
