"""The gate cannot reach the memory of its monitors or co-signers (Phase 3, slice 3).

Once confined (gate_confine.py), the gate (P1) is under Landlock and holds no
capability. Landlock refuses it ptrace, and the calls checked like it, on any
process outside its domain, and the monitor (P0), the co-signers (P2) and
P2's replay monitor (P0') were all started before it confined itself.
Without a capability, the rest is refused as for any process of their user,
since they are undumpable: perf's samples of their stacks among it, which
Landlock alone leaves to a gate running as root.

Each probe is shown to work on a process the confined gate starts itself.
CI runs this file as root as well, where the capabilities matter."""
import os

import pytest

import tests.support  # noqa: F401
import gate_confine
from tests.test_gate_landlock import _confined
from tests.test_jail import needs_jail          # the jail needs Landlock, as confining the gate does

PROBE = r'''
import ctypes, errno, json, os, struct, subprocess, sys
import guarded_agent as ga, gate_confine
W, confine = sys.argv[1], sys.argv[2] == "confined"
gate, L = ga.setup(W)
targets = {"the monitor": gate.monitor.pid, "the co-signers": gate.co_signer._proc.pid,
           "the co-signer's replay monitor": gate.co_signer._proc.replay_monitor_pid}
if confine: gate_confine.confine_gate(W)
own = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], stdin=subprocess.DEVNULL)
targets["a process of its own"] = own.pid
libc = ctypes.CDLL(None, use_errno=True)

class iovec(ctypes.Structure): _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]

def called(r):
    e = ctypes.get_errno()            # EFAULT: let in, at an address not mapped there
    return "reached" if r >= 0 or e == errno.EFAULT else errno.errorcode.get(e, str(e))

def opened(path, n=0):
    try:
        with open(path, "rb") as f: f.read(n)
        return "reached"
    except OSError as e: return errno.errorcode.get(e.errno, str(e))

def perf_attr():                      # cpu-clock samples carrying the user stack and registers
    a = bytearray(112)
    struct.pack_into("IIQQQQQ", a, 0, 1, 112, 0, 100000, (1 << 13) | (1 << 12), 0, (1 << 5) | (1 << 6))
    struct.pack_into("QI", a, 80, 0xff, 4096)
    return (ctypes.c_char * 112).from_buffer(a)

def reach(pid):
    r = {"ptrace": called(libc.ptrace(0x4206, pid, None, None))}             # PTRACE_SEIZE
    buf = ctypes.create_string_buffer(16)
    local, remote = iovec(ctypes.cast(buf, ctypes.c_void_p), 16), iovec(0x1000, 16)
    r["process_vm_readv"] = called(libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0))
    r["/proc/pid/mem"] = opened(f"/proc/{pid}/mem")
    r["/proc/pid/environ"] = opened(f"/proc/{pid}/environ", 1)
    r["/proc/pid/maps"] = opened(f"/proc/{pid}/maps", 1)
    pidfd = libc.syscall(434, pid, 0)                                         # pidfd_open
    fd = libc.syscall(438, pidfd, 0, 0) if pidfd >= 0 else -1                 # pidfd_getfd: its descriptor 0
    r["pidfd_getfd"] = called(fd)
    for d in (fd, pidfd):
        if d >= 0: os.close(d)
    fd = libc.syscall(298, perf_attr(), pid, -1, -1, 8)                       # perf_event_open
    r["perf_event_open"] = called(fd)
    if fd >= 0: os.close(fd)
    return r

with open("/proc/sys/kernel/perf_event_paranoid") as f: paranoid = int(f.read())
out = {"uid": os.getuid(), "threads": gate_confine.threads(), "capabilities": gate_confine.capabilities(),
       "perf_event_paranoid": paranoid, "reach": {name: reach(pid) for name, pid in targets.items()}}
own.kill(); own.wait()
print(json.dumps(out))
'''
METHODS = {"ptrace", "process_vm_readv", "/proc/pid/mem", "/proc/pid/environ", "/proc/pid/maps", "pidfd_getfd",
           "perf_event_open"}
REFUSED = {"EPERM", "EACCES"}

@pytest.fixture(scope="module")
def confined(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("memory")
    return _confined(PROBE, tmp, str(tmp / "work"), "confined")


@needs_jail
def test_the_confined_gate_cannot_reach_the_memory_of_its_monitors_or_co_signers(confined):
    reach = dict(confined["reach"])
    own = reach.pop("a process of its own")
    # Each probe can see a way in. Above 2, perf_event_paranoid may refuse a
    # process without a capability perf even on its own children (Debian and
    # Ubuntu kernels do), so perf is then no way in at all.
    sees = METHODS if confined["perf_event_paranoid"] <= 2 else METHODS - {"perf_event_open"}
    assert set(own) == METHODS and {m for m, r in own.items() if r == "reached"} >= sees, own
    for target, ways in reach.items():
        assert set(ways) == METHODS and set(ways.values()) <= REFUSED, (target, ways)


@needs_jail
def test_the_confined_gate_holds_no_capability(confined):
    caps = confined["capabilities"]
    assert all(caps[k] == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapAmb")), caps
    if confined["uid"] == 0: assert caps["CapBnd"] == 0, caps                # and could not take one back


@pytest.mark.skipif(os.getuid() != 0, reason="as any other user, PR_SET_DUMPABLE alone refuses these")
def test_unconfined_and_root_the_gate_reaches_them_all(tmp_path):
    """What the confinement takes away: run as root and unconfined, the gate
    reaches every one of them every way."""
    out = _confined(PROBE, tmp_path, str(tmp_path / "work"), "unconfined")
    for target, ways in out["reach"].items():
        assert set(ways.values()) == {"reached"}, (target, ways)


THREADED = r'''
import json, os, sys, threading, time
import gate_confine
os.makedirs(sys.argv[1], exist_ok=True)
threading.Thread(target=time.sleep, args=(60,), daemon=True).start()
try: gate_confine.confine_gate(sys.argv[1]); print(json.dumps({"refused": None}))
except gate_confine.Refused as e: print(json.dumps({"refused": str(e)}))
'''

@needs_jail
def test_a_gate_with_another_thread_is_not_confined(tmp_path):
    """Landlock and capabilities are a thread's: another thread would keep both."""
    out = _confined(THREADED, tmp_path, str(tmp_path / "work"))
    assert out["refused"] and "threads" in out["refused"], out


HOLDING = r'''
import json, os, sys
import gate_confine
os.makedirs(sys.argv[1], exist_ok=True)
try: gate_confine.check(sys.argv[1]); print(json.dumps({"refused": None}))
except gate_confine.Refused as e: print(json.dumps({"refused": str(e)}))
'''

@pytest.mark.skipif(os.getuid() != 0, reason="a process of any other user holds no capability to find")
def test_a_gate_that_still_holds_a_capability_is_refused(tmp_path):
    out = _confined(HOLDING, tmp_path, str(tmp_path / "work"))
    assert out["refused"] and "capabilities" in out["refused"], out
