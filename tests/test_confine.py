"""confine.py: the Landlock ruleset and seccomp filter a jailed command runs under.

The filter is checked by running it: a small classic-BPF interpreter executes
the program confine.py would load, so a wrong jump offset or a missing number
shows up as a wrong verdict for a real system call, not as a different list.
What the kernel does with both layers is probed in tests/test_containment.py."""
import errno
import pathlib
import re
import types

import pytest

import tests.support  # noqa: F401
import confine
import jail
from tests.test_jail import needs_jail

# Numbers of calls the trace does see, which must stay allowed.
ALLOWED = {"x86_64": {"read": 0, "openat": 257, "execve": 59, "clone3": 435},
           "aarch64": {"read": 63, "openat": 56, "execve": 221, "clone3": 435}}
DENY = confine.SECCOMP_RET_ERRNO | errno.ENOSYS


def verdict(prog, arch, nr):
    """Run a classic-BPF program over seccomp_data {nr, arch}."""
    acc, pc = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        if code == confine.BPF_LD_W_ABS:
            acc = {0: nr, 4: arch}[k]; pc += 1
        elif code == confine.BPF_JEQ_K:
            pc += 1 + (jt if acc == k else jf)
        elif code == confine.BPF_JGE_K:
            pc += 1 + (jt if acc >= k else jf)
        elif code == confine.BPF_RET_K:
            return k
        else:
            raise AssertionError(f"unexpected opcode {code:#x}")


@pytest.mark.parametrize("machine", sorted(confine.SYSCALL_TABLES))
def test_the_filter_refuses_exactly_the_untraced_calls(machine):
    arch, numbers = confine.SYSCALL_TABLES[machine]
    prog = confine.seccomp_program(machine)
    assert set(numbers) == set(confine.DENIED)
    for name in confine.DENIED:
        assert verdict(prog, arch, numbers[name]) == DENY, name
    for name, nr in ALLOWED[machine].items():
        assert verdict(prog, arch, nr) == confine.SECCOMP_RET_ALLOW, name


@pytest.mark.parametrize("machine", sorted(confine.SYSCALL_TABLES))
def test_calls_under_another_arch_are_refused(machine):
    """32-bit compat calls carry another arch value and other numbers."""
    arch, numbers = confine.SYSCALL_TABLES[machine]
    prog = confine.seccomp_program(machine)
    assert verdict(prog, 0x40000003, numbers["openat2"]) == DENY     # AUDIT_ARCH_I386
    assert verdict(prog, 0x40000003, 5) == DENY                       # i386 open


def test_x32_calls_are_refused():
    arch, _ = confine.SYSCALL_TABLES["x86_64"]
    prog = confine.seccomp_program("x86_64")
    assert verdict(prog, arch, confine.X32_SYSCALL_BIT | 257) == DENY


# The numbers again, written down separately from confine.py's table, from
# arch/x86/entry/syscalls/syscall_64.tbl and include/uapi/asm-generic/unistd.h.
REFERENCE = {"x86_64": {"openat2": 437, "execveat": 322, "io_uring_setup": 425, "io_uring_enter": 426,
                        "io_uring_register": 427, "open_by_handle_at": 304, "name_to_handle_at": 303},
             "aarch64": {"openat2": 437, "execveat": 281, "io_uring_setup": 425, "io_uring_enter": 426,
                         "io_uring_register": 427, "open_by_handle_at": 265, "name_to_handle_at": 264}}
HEADERS = {"x86_64": pathlib.Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
           "aarch64": pathlib.Path("/usr/include/asm-generic/unistd.h")}


def test_the_syscall_numbers_are_the_kernels():
    """A wrong number would leave the real call open and refuse an unrelated one."""
    assert {m: t for m, (_, t) in confine.SYSCALL_TABLES.items()} == REFERENCE


@pytest.mark.parametrize("machine", sorted(HEADERS))
def test_the_syscall_numbers_match_the_installed_headers(machine):
    if not HEADERS[machine].exists():
        pytest.skip(f"{HEADERS[machine]} not installed (linux-libc-dev)")
    text = HEADERS[machine].read_text()
    for name, nr in confine.SYSCALL_TABLES[machine][1].items():
        assert re.search(rf"#define __NR_{name}\s+{nr}\b", text), f"{machine} {name} is not {nr}"


def test_an_unknown_machine_is_refused_not_guessed():
    with pytest.raises(confine.Refused):
        confine.seccomp_program("mips")


def test_every_filesystem_right_the_abi_knows_is_handled():
    assert confine.handled_access(1) == (1 << 13) - 1
    assert confine.handled_access(2) == (1 << 14) - 1
    assert confine.handled_access(3) == confine.handled_access(4) == (1 << 15) - 1
    assert confine.handled_access(5) == confine.handled_access(7) == (1 << 16) - 1


def test_without_landlock_nothing_runs():
    """A kernel without Landlock: confine refuses instead of exec'ing the command."""
    fake = types.SimpleNamespace(prctl=lambda *a: 0, syscall=lambda *a: -1)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(confine, "_libc", lambda: fake)
        with pytest.raises(confine.Refused, match="Landlock"):
            confine.confine("/tmp")


def test_bad_usage_runs_nothing(capsys):
    assert confine.main(["confine.py", "/tmp", "sh"]) == 126
    assert "dharma-jail:" in capsys.readouterr().err


@needs_jail
def test_a_refusal_inside_the_jail_is_reported_and_nothing_runs(tmp_path, monkeypatch):
    """When confine.py refuses, the jail says so and is unavailable: the
    command is never run some other way."""
    fake = tmp_path / "confine.py"
    fake.write_text('import sys\nprint("dharma-jail: refusing to run unconfined: test", file=sys.stderr)\n'
                    'sys.exit(126)\n')
    monkeypatch.setattr(jail, "CONFINE", str(fake))
    w = tmp_path / "w"; w.mkdir()
    with pytest.raises(jail.JailUnavailable, match="dharma-jail: refusing to run unconfined: test"):
        jail.run("echo ran > ran", str(w))
    assert not (w / "ran").exists()
    ok, why = jail.available()
    assert not ok and "dharma-jail" in why
