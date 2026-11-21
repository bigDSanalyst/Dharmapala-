"""Confine a jailed command before it runs: a Landlock ruleset and a seccomp filter.

jail.py starts this inside bubblewrap, in place of the command, and it execs
the command once both are in force:

    python3 -I -c "$(cat confine.py)" WORKDIR -- sh -c CMD

(the source, not the path: the jail may not see where this file is).

Landlock   the command may read and execute only beneath the system
           directories (READ_ROOTS), and may write only beneath the workdir
           and the jail's own /tmp and /dev. The kernel enforces this at the
           LSM layer, whichever system call the command opens a file with, so
           what it can reach no longer depends on what strace was told to
           trace.
seccomp    the system calls that open or execute a file without passing
           through a call strace traces (DENIED) fail with ENOSYS, as if the
           kernel lacked them. Programs that try them fall back to openat and
           execve, which the trace shows, so the guard judges what actually
           happened inside the space Landlock allows. socket(AF_UNIX, ...)
           fails with EPERM: Landlock does not stop a connect to a socket
           file, so a host daemon's socket that the binds missed stays out of
           reach. socketpair, which programs use among their own processes,
           is a different call and still works.

Fail closed: if either cannot be put in place, nothing runs. This prints
"dharma-jail: <why>" and exits 126 without starting the command, and jail.py
reports the jail as unavailable rather than running anything unconfined.

Only the standard library, and nothing newer than Python 3.8: this runs with
whatever python3 the jail's PATH finds, not the interpreter running the guard.
"""
import ctypes
import errno
import os
import platform
import sys

# Read and execute only. /usr covers /usr/local; /proc is the jail's own.
READ_ROOTS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/proc")
# The jail's own, made fresh by bubblewrap: a tmpfs on /tmp and a minimal /dev.
PRIVATE_RW = ("/tmp", "/dev")

# --- Landlock (include/uapi/linux/landlock.h) --------------------------------
SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
ACCESS_EXECUTE, ACCESS_READ_FILE, ACCESS_READ_DIR = 1 << 0, 1 << 2, 1 << 3
PR_SET_NO_NEW_PRIVS = 38


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def handled_access(abi):
    """Every filesystem right the kernel's Landlock ABI knows: ABI 1 has 13,
    2 adds REFER, 3 TRUNCATE, 4 only network rights, 5 IOCTL_DEV. Handling all
    of them means anything not granted below is denied."""
    return (1 << {1: 13, 2: 14, 3: 15, 4: 15}.get(abi, 16)) - 1


# --- seccomp (include/uapi/linux/seccomp.h, filter.h, audit.h) ---------------
PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 22, 2
SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO = 0x7FFF0000, 0x00050000
BPF_LD_W_ABS, BPF_JEQ_K, BPF_JGE_K, BPF_RET_K = 0x20, 0x15, 0x35, 0x06
X32_SYSCALL_BIT = 0x40000000
# (audit arch, {name: number}) per machine. Calls made under any other arch
# value (32-bit compat calls from a 64-bit process) are all denied.
SYSCALL_TABLES = {
    "x86_64": (0xC000003E, {"openat2": 437, "execveat": 322, "io_uring_setup": 425,
                            "io_uring_enter": 426, "io_uring_register": 427,
                            "open_by_handle_at": 304, "name_to_handle_at": 303, "socket": 41}),
    "aarch64": (0xC00000B7, {"openat2": 437, "execveat": 281, "io_uring_setup": 425,
                             "io_uring_enter": 426, "io_uring_register": 427,
                             "open_by_handle_at": 265, "name_to_handle_at": 264, "socket": 198}),
}
AF_UNIX = 1
# socket()'s domain is a C int: the kernel reads only the low 32 bits of the
# 64-bit argument, so the filter compares those and nothing else. Comparing all
# 64 would let 1 | 1 << 32 through as a family the filter does not know while
# the kernel made an AF_UNIX socket of it. Both machines here are little-endian:
# seccomp_data.args[0] is at offset 16, its low word first.
ARG0_LOW = 16
DENIED = ("openat2", "execveat", "io_uring_setup", "io_uring_enter", "io_uring_register",
          "open_by_handle_at", "name_to_handle_at")


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8),
                ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


class Refused(Exception):
    """The command must not run: confinement could not be put in place."""


def _libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def _fail(what):
    err = ctypes.get_errno()
    raise Refused(f"{what}: {os.strerror(err)}" if err else what)


def _landlock(libc, workdir):
    abi = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 1:
        _fail("Landlock is not available")
    handled = handled_access(abi)
    attr = _RulesetAttr(handled)
    rfd = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0:
        _fail("landlock_create_ruleset")
    try:
        def allow(path, access):
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = _PathBeneath(access & handled, fd)
                if libc.syscall(SYS_LANDLOCK_ADD_RULE, rfd, LANDLOCK_RULE_PATH_BENEATH,
                                ctypes.byref(rule), 0) < 0:
                    _fail(f"landlock_add_rule {path}")
            finally:
                os.close(fd)
        for root in READ_ROOTS:
            if os.path.isdir(root) and not os.path.islink(root):
                allow(root, ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR)
        for root in PRIVATE_RW:
            if os.path.isdir(root):
                allow(root, handled)
        allow(workdir, handled)
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, rfd, 0) < 0:
            _fail("landlock_restrict_self")
    finally:
        os.close(rfd)
    return abi


def seccomp_program(machine):
    """The classic-BPF filter for `machine`, as (code, jt, jf, k) tuples."""
    if machine not in SYSCALL_TABLES:
        raise Refused(f"no seccomp syscall table for {machine}")
    arch, numbers = SYSCALL_TABLES[machine]
    deny = SECCOMP_RET_ERRNO | errno.ENOSYS
    prog = [(BPF_LD_W_ABS, 0, 0, 4),            # seccomp_data.arch
            (BPF_JEQ_K, 1, 0, arch),
            (BPF_RET_K, 0, 0, deny),            # a foreign arch: compat calls
            (BPF_LD_W_ABS, 0, 0, 0)]            # seccomp_data.nr
    if machine == "x86_64":
        prog += [(BPF_JGE_K, 0, 1, X32_SYSCALL_BIT), (BPF_RET_K, 0, 0, deny)]
    for name in DENIED:
        prog += [(BPF_JEQ_K, 0, 1, numbers[name]), (BPF_RET_K, 0, 0, deny)]
    prog += [(BPF_JEQ_K, 0, 3, numbers["socket"]),     # not socket(): allow
             (BPF_LD_W_ABS, 0, 0, ARG0_LOW),            # the domain's low 32 bits
             (BPF_JEQ_K, 0, 1, AF_UNIX),
             (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM)]
    return prog + [(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]


def _seccomp(libc):
    prog = seccomp_program(platform.machine())
    filt = (_SockFilter * len(prog))(*[_SockFilter(c, jt, jf, k) for c, jt, jf, k in prog])
    fprog = _SockFprog(len(prog), filt)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        _fail("seccomp filter")


def confine(workdir):
    """Put both layers in place on this process, for good. Raises Refused."""
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        _fail("PR_SET_NO_NEW_PRIVS")
    _landlock(libc, workdir)
    _seccomp(libc)


def main(argv):
    if len(argv) < 4 or argv[2] != "--":
        print("dharma-jail: usage: confine.py WORKDIR -- CMD [ARG...]", file=sys.stderr)
        return 126
    try:
        confine(os.path.realpath(argv[1]))
    except (Refused, OSError) as e:
        print(f"dharma-jail: refusing to run unconfined: {e}", file=sys.stderr)
        return 126
    try:
        os.execvp(argv[3], argv[3:])
    except OSError as e:
        print(f"dharma-jail: cannot run {argv[3]}: {e}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv))
