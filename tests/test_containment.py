"""What the jail contains, probed so that breaking the jail is safe.

Each probe checks one containment property against something the test owns:
a sibling directory it made, a sentinel process it started, a socket it is
listening on, an environment variable it set. So the probes can run against a
deliberately broken jail (containment_mutants.py does exactly that, one
bubblewrap flag at a time) without anything real being written, killed or
reached. A probe that sees the jail fail says ESCAPE:, which is how the
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
