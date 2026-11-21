"""Calls the jail's filter refuses are recorded, not judged.

confine.py's seccomp filter refuses openat2, execveat, io_uring, file handles
and socket(AF_UNIX). Containment does not need to see them: Landlock bounds
what any call can reach, and a refused call does nothing. But an attempt is
worth keeping (docs/monitor-boundary.md, section 5), so jail.SYSCALLS traces
them, and both parsers record each one that failed as a "refused" event:
(call, what it named, errno). It is telemetry, never an effect: glibc's name
lookups try socket(AF_UNIX) in ordinary commands.

strace sees a call the filter refused only because it stops at every traced
call itself. With --seccomp-bpf, the filter's errno outranks strace's trace
stop and the call vanishes from the trace. The end-to-end test here is what
pins that."""
import os
import platform

import pytest

import tests.support  # noqa: F401
import confine
import jail
import witness
from tests.test_jail import needs_jail


def test_every_call_the_filter_refuses_is_traced():
    traced = set(jail.SYSCALLS.split(","))
    for machine, (_, numbers) in confine.SYSCALL_TABLES.items():
        assert set(numbers) <= traced, machine
        assert set(numbers) == set(jail.REFUSABLE) == set(witness._REFUSABLE), machine


TRACE = {1: "\n".join([
    'execve("/bin/sh", ["sh", "-c", "probe"], 0x7ffd /* 3 vars */) = 0',
    'openat2(AT_FDCWD</w>, "/etc/hostname", {flags=O_RDONLY, resolve=0}, 24) = -1 ENOSYS (Function not implemented)',
    'openat2(AT_FDCWD</w>, "notes.txt", {flags=O_RDONLY, resolve=0}, 24) = -1 ENOSYS (Function not implemented)',
    'io_uring_setup(1, NULL)                 = -1 ENOSYS (Function not implemented)',
    'execveat(AT_FDCWD</w>, "/bin/true", ["true"], 0x7ffd /* 3 vars */, 0) = -1 ENOSYS (Function not implemented)',
    'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = -1 EPERM (Operation not permitted)',
    'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3<socket:[1]>',
])}
EXPECTED = [
    ("refused", ("openat2", os.path.realpath("/etc/hostname"), "ENOSYS"), False),
    ("refused", ("openat2", "/w/notes.txt", "ENOSYS"), False),
    ("refused", ("io_uring_setup", "", "ENOSYS"), False),
    ("refused", ("execveat", os.path.realpath("/bin/true"), "ENOSYS"), False),
    ("refused", ("socket", "AF_UNIX", "EPERM"), False),
]


@pytest.mark.parametrize("parse", [jail.parse, witness.parse], ids=["guard", "co-signer"])
def test_each_parser_records_a_refused_call_and_not_an_allowed_socket(parse):
    assert parse(TRACE, "probe") == EXPECTED


def test_a_refused_call_is_no_effect():
    sensitive = ("refused", ("openat2", "/root/.ssh/id_test", "ENOSYS"), False)
    assert jail.effects_of(EXPECTED + [sensitive], "/w") == {"exec"}


NR = confine.SYSCALL_TABLES.get(platform.machine(), (0, {}))[1]
PROBE = (
    "python3 -c '\n"
    "import ctypes, socket\n"
    "L = ctypes.CDLL(None, use_errno=True); L.syscall.restype = ctypes.c_long\n"
    "c = ctypes.c_long\n"
    "how = (ctypes.c_uint64 * 3)(0, 0, 0)\n"
    f"L.syscall(c({NR.get('openat2')}), c(-100), b\"/etc/hostname\", ctypes.byref(how), c(24))\n"
    f"L.syscall(c({NR.get('io_uring_setup')}), c(1), c(0))\n"
    f"L.syscall(c({NR.get('execveat')}), c(-100), b\"/bin/true\", c(0), c(0), c(0))\n"
    "try: socket.socket(socket.AF_UNIX)\n"
    "except OSError: pass\n"
    "'"
)


@needs_jail
@pytest.mark.skipif(not NR, reason="no syscall table for this machine")
def test_a_jailed_attempt_at_a_refused_call_is_in_the_record(tmp_path):
    ex = jail.run(PROBE, str(tmp_path))
    refused = {d[0]: d for k, d, _ in ex.events if k == "refused"}
    assert refused.get("openat2") == ("openat2", os.path.realpath("/etc/hostname"), "ENOSYS"), ex.events
    assert refused.get("io_uring_setup") == ("io_uring_setup", "", "ENOSYS")
    assert refused.get("execveat") == ("execveat", os.path.realpath("/bin/true"), "ENOSYS")
    assert refused.get("socket") == ("socket", "AF_UNIX", "EPERM")
    assert witness.parse(ex.trace, PROBE) == ex.events          # the co-signer reads them the same way
    judged = [e for e in ex.events if e[0] != "refused"]
    assert jail.effects_of(ex.events, str(tmp_path)) == jail.effects_of(judged, str(tmp_path))
