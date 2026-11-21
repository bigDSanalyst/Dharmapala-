"""CW-VFS fixes D11 and D12, on any filesystem.

D11: a snapshot (a rehearsal's copy, a replay's) is the workdir as it was:
empty directories kept, every directory's and file's exact mode kept, the
atomic writer's temp files left out, no descriptor leaked. mkdir_confined is
how its directories are made.

D12: device numbers are not an invariant. Overlay and passthrough filesystems
give inodes of one mount different st_dev values, and a jail that compared
them refused every file operation there. Cross-mount confinement is
RESOLVE_NO_XDEV's, enforced by the kernel on each openat2. The real overlay is
tests/test_cw_vfs_overlay.py (it needs root); here the per-inode devices are
simulated, so the rule is checked everywhere."""
import errno
import os
import stat

import pytest

import tests.support  # noqa: F401
import cw_vfs
from cw_vfs import (CapabilityDirJail, CapabilityWitness, ConfinementViolation,
                    clone_confined_snapshot, verify_witness_against_call)
from tools import Sandbox
from to_coq_witness import Certificate, build_certificate


def mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


# --- D11a: mkdir_confined --------------------------------------------------------------------

def test_mkdir_confined_sets_the_exact_mode_whatever_the_umask(tmp_path):
    old = os.umask(0o077)
    try:
        with CapabilityDirJail(tmp_path) as j:
            j.mkdir_confined("a/b", 0o755)
            assert mode(tmp_path / "a" / "b") == 0o755
            j.mkdir_confined("a/b", 0o700)              # idempotent; the mode is set again
            assert mode(tmp_path / "a" / "b") == 0o700
    finally:
        os.umask(old)


def test_mkdir_confined_refuses_special_bits(tmp_path):
    with CapabilityDirJail(tmp_path) as j, pytest.raises(ConfinementViolation) as e:
        j.mkdir_confined("x", 0o2755)
    assert e.value.errno_code == errno.EPERM and not (tmp_path / "x").exists()


def test_mkdir_confined_does_not_follow_a_symlink_out(tmp_path):
    out, w = tmp_path / "out", tmp_path / "w"
    out.mkdir(); w.mkdir(); (w / "link").symlink_to(out)
    with CapabilityDirJail(w) as j, pytest.raises(ConfinementViolation):
        j.mkdir_confined("link/x")
    assert not (out / "x").exists()


# --- D11b/c: the snapshot --------------------------------------------------------------------

@pytest.fixture
def src(tmp_path):
    s = tmp_path / "src"
    (s / "empty").mkdir(parents=True)
    (s / "priv").mkdir(); os.chmod(s / "priv", 0o700)
    (s / "priv" / "run.sh").write_text("#!/bin/sh\necho hi\n"); os.chmod(s / "priv" / "run.sh", 0o755)
    (s / "a" / "b").mkdir(parents=True); (s / "a" / "b" / "notes.txt").write_text("notes\n")
    (s / ".dharma_tmp_0123").write_text("an atomic write in progress")
    return s


def test_a_snapshot_keeps_empty_directories_and_exact_modes(tmp_path, src):
    old = os.umask(0o022)
    try:
        clone_confined_snapshot(src, tmp_path / "dst")
    finally:
        os.umask(old)
    d = tmp_path / "dst"
    assert (d / "empty").is_dir()
    assert mode(d / "priv") == 0o700, "a 0700 directory was widened"
    assert mode(d / "priv" / "run.sh") == 0o755
    assert (d / "a" / "b" / "notes.txt").read_text() == "notes\n"
    assert not (d / ".dharma_tmp_0123").exists()


def test_a_snapshot_leaks_no_descriptor(tmp_path, src):
    before = set(os.listdir("/proc/self/fd"))
    clone_confined_snapshot(src, tmp_path / "dst")
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("make", ["symlink", "hardlink", "fifo"])
def test_a_snapshot_refuses_what_is_not_a_plain_file_or_directory(tmp_path, src, make):
    target = src / "a" / "b" / "odd"
    if make == "symlink": target.symlink_to("/etc/hostname")
    elif make == "hardlink": os.link(src / "a" / "b" / "notes.txt", target)
    else: os.mkfifo(target)
    with pytest.raises(ConfinementViolation):
        clone_confined_snapshot(src, tmp_path / "dst")


# --- D12: per-inode device numbers -----------------------------------------------------------

@pytest.fixture
def per_inode_devices(monkeypatch):
    """Regular files report a device the directories do not, as on an overlay
    whose lower layer is another filesystem. Both stat calls cw_vfs makes are
    shifted alike, so a file still matches its own directory entry."""
    real_fstat, real_stat = os.fstat, os.stat
    def shift(st):
        if not stat.S_ISREG(st.st_mode): return st
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 7, st.st_nlink, st.st_uid, st.st_gid,
                               st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
    monkeypatch.setattr(cw_vfs.os, "fstat", lambda fd: shift(real_fstat(fd)))
    monkeypatch.setattr(cw_vfs.os, "stat", lambda *a, **k: shift(real_stat(*a, **k)))


def test_files_on_another_device_than_their_directory_are_read_and_written(tmp_path, per_inode_devices):
    (tmp_path / "sub").mkdir(); (tmp_path / "sub" / "f.txt").write_text("hello\n")
    with CapabilityDirJail(tmp_path) as j:
        data, _, w = j.read_bytes("sub/f.txt")
        assert data == b"hello\n" and w.leaf_dev != w.root_dev
        ww = j.write_bytes_atomic("sub/g.txt", b"x")
        assert ww.leaf_dev != ww.root_dev


def test_a_witness_with_two_devices_verifies_and_its_theorem_holds(tmp_path, per_inode_devices):
    sb = Sandbox(tmp_path)
    try:
        assert sb.file_write("notes/a.txt", "dharma")["ok"]
        assert sb.file_read("notes/a.txt")["ok"]
    finally:
        sb.close()
    for tool, kwargs, result in sb.calls:
        wit = CapabilityWitness.from_dict(result["capability_witness"])
        assert wit.root_dev != wit.leaf_dev
        ok, why, _ = verify_witness_against_call(wit, tool, kwargs, result)
        assert ok, why
    cert = build_certificate("d12", {"butterflies": []}, evidence={"workdir": str(tmp_path), "calls": sb.calls})
    assert "rdev =?" not in " ".join(w.statement for w in cert.witnesses)
    with cert.emitted() as path:
        ok, out = Certificate.check(path)
    if ok is None:
        pytest.skip(f"coqc not available: {out}")
    assert ok, out


# --- the file tools --------------------------------------------------------------------------

def test_a_read_cut_inside_a_character_returns_the_text_before_it(tmp_path):
    """file_read returns at most 2000 bytes. Where the cut falls inside a
    multi-byte character, the read stops before it rather than failing, and
    the witness still covers exactly the bytes returned."""
    (tmp_path / "t.txt").write_text("a" * 1999 + "\u00e9" + "tail", encoding="utf-8")
    sb = Sandbox(tmp_path)
    try:
        r = sb.file_read("t.txt")
    finally:
        sb.close()
    assert r["ok"] and r["truncated"] and r["content"] == "a" * 1999, r.get("error")
    tool, kwargs, result = sb.calls[0]
    ok, why, _ = verify_witness_against_call(CapabilityWitness.from_dict(result["capability_witness"]),
                                             tool, kwargs, result)
    assert ok, why


def test_a_file_that_is_not_text_is_still_an_error(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\xff\xfe\x00binary")
    sb = Sandbox(tmp_path)
    try:
        assert not sb.file_read("b.bin")["ok"]
    finally:
        sb.close()


def test_file_read_does_not_reach_a_credentials_file_outside_the_workdir(tmp_path):
    """The file tools used to follow an absolute path anywhere, so the model
    could be handed ~/.aws/credentials. Absolute, climbing with .., or through
    a symlink inside the workdir: each is refused."""
    home = tmp_path / "home"; (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text("DHARMA-DUMMY-CREDENTIALS\n")
    w = tmp_path / "w"; w.mkdir(); (w / "link").symlink_to(home / ".aws")
    target = str(home / ".aws" / "credentials")
    sb = Sandbox(w)
    try:
        for path in (target, "../" * 12 + target.lstrip("/"), "link/credentials"):
            r = sb.file_read(path)
            assert not r["ok"] and "DHARMA-DUMMY" not in str(r), path
    finally:
        sb.close()
