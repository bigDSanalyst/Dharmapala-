"""Adversarial verification suite for cw_vfs.py (CW-VFS confinement).

Every attack below is executed against the real kernel (SYS_openat2 strict
resolve) on Linux >= 5.6. Run:  python3 -m pytest test_cw_vfs.py -q
"""
import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess

import pytest

import cw_vfs
from cw_vfs import (
    RESOLVE_STRICT_MASK,
    CapabilityDirJail,
    CapabilityWitness,
    ConfinementViolation,
    clone_confined_snapshot,
    verify_witness_against_call,
)

COQC = shutil.which("coqc")


# ---------------------------------------------------------------- helpers

@pytest.fixture()
def jail(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    with CapabilityDirJail(root) as j:
        yield j


def seed(root: pathlib.Path, rel: str, data: bytes):
    p = pathlib.Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


# ---------------------------------------------------------------- plumbing

def test_openat2_plumbing():
    assert cw_vfs._SYS_NR == 437
    assert RESOLVE_STRICT_MASK == 0x0F
    assert cw_vfs._LIBC is not None


def test_jail_close_idempotent(tmp_path):
    before = fd_count()
    root = tmp_path / "w"
    root.mkdir()
    for _ in range(5):
        j = CapabilityDirJail(root)
        j.close()
        j.close()
    assert fd_count() - before < 3


# ---------------------------------------------------------------- basics

def test_read_write_roundtrip_witness(jail):
    wit = jail.write_bytes_atomic("f.txt", b"hello world", mode=0o644)
    assert wit.op == "write" and wit.confined and wit.resolve_flags == 0x0F
    assert wit.content_sha256 == hashlib.sha256(b"hello world").hexdigest()
    assert wit.leaf_nlink == 1 and wit.root_dev == jail.root_dev
    data, truncated, rwit = jail.read_bytes("f.txt")
    assert data == b"hello world" and truncated is False
    # D12: leaf_dev is per-inode metadata on overlay fs (files 44, dirs 43); only
    # same-inode stability is asserted (write then read must pin the same leaf).
    assert rwit.leaf_dev == wit.leaf_dev and rwit.leaf_ino == wit.leaf_ino
    assert rwit.op == "read" and rwit.content_sha256 == wit.content_sha256
    assert rwit.requested_path == "f.txt" and rwit.rel_lexical_path == "f.txt"
    ok, why, _ = verify_witness_against_call(
        rwit, "file_read", {"path": "f.txt"},
        {"content": data.decode(), "content_sha256": rwit.content_sha256},
    )
    assert ok, why


def test_witness_hop_chain_nested(jail):
    jail.write_bytes_atomic("a/b/c.txt", b"payload")
    _, _, wit = jail.read_bytes("a/b/c.txt")
    assert wit.expected_hops == 4 and len(wit.hop_inodes) == 4
    assert wit.hop_inodes[0] == jail.root_ino
    assert wit.hop_inodes[-1] == wit.leaf_ino
    assert all(i > 0 for i in wit.hop_inodes)
    assert wit.fd_realpath.startswith(jail.root_path.rstrip("/") + "/")


def test_witness_serialization_roundtrip(jail):
    jail.write_bytes_atomic("d/f.txt", b"payload")
    _, _, wit = jail.read_bytes("d/f.txt")
    d = wit.to_dict()
    assert json.loads(json.dumps(d)) == d  # JSON-stable (ledger-codable)
    wit2 = CapabilityWitness.from_dict(d)
    assert wit2 == wit
    assert isinstance(wit2.hop_inodes, tuple)


# ---------------------------------------------------------------- escapes

@pytest.mark.parametrize("bad_path", [
    "/etc/passwd",
    "../../../etc/passwd",
    "a/../../etc/passwd",
    "/a/../b",
    "..",
])
def test_escape_rejected(jail, bad_path):
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes(bad_path)
    assert ei.value.errno_code in (errno.EXDEV, errno.EINVAL)


def test_absolute_prefix_collision_rejected(tmp_path, jail):
    seed(jail.root_path, "aa/f.txt", b"x")  # sibling dir "aa", root is ".../work"
    sibling = pathlib.Path(jail.root_path).parent / "workX" / "f.txt"
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes(str(sibling))
    assert ei.value.errno_code == errno.EXDEV


def test_absolute_inside_root_maps(jail):
    seed(jail.root_path, "a.txt", b"mapped")
    data, _, wit = jail.read_bytes(str(pathlib.Path(jail.root_path) / "a.txt"))
    assert data == b"mapped" and wit.rel_lexical_path == "a.txt"


def test_logical_workdir_mapping(tmp_path):
    real_wd = tmp_path / "orig"
    (real_wd / "sub").mkdir(parents=True)
    (real_wd / "sub" / "f.txt").write_bytes(b"hello")
    copy = tmp_path / "copy"
    clone_confined_snapshot(real_wd, copy)  # as critic_loop.rehearse does
    with CapabilityDirJail(copy, logical_workdir=str(real_wd)) as j:
        data, _, wit = j.read_bytes(str(real_wd / "sub" / "f.txt"))
        assert data == b"hello" and wit.rel_lexical_path == "sub/f.txt"
        j.write_bytes_atomic(str(real_wd / "sub" / "g.txt"), b"new")
        assert (copy / "sub" / "g.txt").read_bytes() == b"new"
    with CapabilityDirJail(copy, logical_workdir=str(real_wd)) as j:
        with pytest.raises(ConfinementViolation) as ei:
            j.read_bytes("/etc/passwd")  # under neither root nor logical root
        assert ei.value.errno_code == errno.EXDEV


def test_root_itself_rejected(jail):
    for p in (str(pathlib.Path(jail.root_path)),):
        with pytest.raises(ConfinementViolation) as ei:
            jail.read_bytes(p)
        assert ei.value.errno_code == errno.EISDIR
        with pytest.raises(ConfinementViolation):
            jail.write_bytes_atomic(p, b"x")


@pytest.mark.parametrize("bad", ["", "   ", ".", "./", "a\x00b", None])
def test_invalid_paths_rejected(jail, bad):
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes(bad)
    assert ei.value.errno_code == errno.EINVAL


def test_benign_relative_dotdot(jail):
    seed(jail.root_path, "a/b.txt", b"ok")
    seed(jail.root_path, "a/missing_none", b"x")  # ensure 'a' is a real dir
    data, _, _ = jail.read_bytes("a/b/../b.txt")
    assert data == b"ok"


def test_dotdot_through_missing_component_collapses_in_jail(jail):
    seed(jail.root_path, "a/b.txt", b"ok")
    data, _, _ = jail.read_bytes("a/missing/../b.txt")
    assert data == b"ok"


def test_symlink_before_dotdot_rejected(jail):
    d = pathlib.Path(jail.root_path) / "d"
    d.mkdir()
    os.symlink("/", d / "x")
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("d/x/../../etc/passwd")
    assert ei.value.errno_code == errno.ELOOP
    with pytest.raises(ConfinementViolation):
        jail.read_bytes("d/x/..")  # even the bare pop is refused


# ---------------------------------------------------------------- symlink/fifo/hardlink

def test_symlink_leaf_rejected(jail):
    seed(jail.root_path, "f.txt", b"x")
    os.symlink("f.txt", pathlib.Path(jail.root_path) / "sym")  # even in-jail target refused
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("sym")
    assert ei.value.errno_code == errno.ELOOP
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic("sym", b"y")
    assert ei.value.errno_code == errno.ELOOP


def test_symlinked_parent_rejected(jail):
    os.symlink("/etc", pathlib.Path(jail.root_path) / "symdir")
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("symdir/passwd")
    # Kernel 5.10 openat2(O_DIRECTORY|NO_SYMLINKS) rejects the component with
    # ENOTDIR; newer kernels may report ELOOP. Either is a hard confinement.
    assert ei.value.errno_code in (errno.ELOOP, errno.ENOTDIR)


def test_magiclink_rejected(jail):
    os.symlink("/proc/self/root", pathlib.Path(jail.root_path) / "magic")
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("magic")
    assert ei.value.errno_code == errno.ELOOP


def test_fifo_rejected(jail):
    os.mkfifo(pathlib.Path(jail.root_path) / "pipe")
    with pytest.raises(ConfinementViolation) as ei:  # must not hang (O_NONBLOCK defusal)
        jail.read_bytes("pipe")
    assert ei.value.errno_code == errno.EINVAL
    with pytest.raises(ConfinementViolation):
        jail.write_bytes_atomic("pipe", b"y")


def test_hardlink_leaf_rejected(jail):
    f = seed(jail.root_path, "f.txt", b"x")
    os.link(f, pathlib.Path(jail.root_path) / "g.txt")
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("g.txt")
    assert ei.value.errno_code == errno.EMLINK
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic("g.txt", b"y")
    assert ei.value.errno_code == errno.EMLINK


def test_directory_as_file_rejected(jail):
    (pathlib.Path(jail.root_path) / "sub").mkdir()
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("sub")
    assert ei.value.errno_code == errno.EINVAL


def test_read_nonexistent(jail):
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes("nope.txt")
    assert ei.value.errno_code == errno.ENOENT


def test_name_too_long(jail):
    long_name = "A" * 256
    with pytest.raises(ConfinementViolation) as ei:
        jail.read_bytes(long_name)
    assert ei.value.errno_code == errno.ENAMETOOLONG
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic(long_name, b"x")
    assert ei.value.errno_code == errno.ENAMETOOLONG
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic(f"{long_name}/f.txt", b"x")
    assert ei.value.errno_code == errno.ENAMETOOLONG


# ---------------------------------------------------------------- truncation / sha

def test_truncation_exact_boundary(jail):
    seed(jail.root_path, "f.bin", b"A" * 4)
    data, truncated, wit = jail.read_bytes("f.bin", max_bytes=4)
    assert data == b"AAAA" and truncated is False
    assert wit.content_sha256 == hashlib.sha256(b"AAAA").hexdigest()


def test_truncation_over(jail):
    seed(jail.root_path, "f.bin", b"A" * 10)
    data, truncated, wit = jail.read_bytes("f.bin", max_bytes=4)
    assert data == b"AAAA" and truncated is True
    assert wit.content_sha256 == hashlib.sha256(b"AAAA").hexdigest()
    assert wit.truncated is True


# ---------------------------------------------------------------- writes

def test_write_atomic_replaces_existing(jail):
    seed(jail.root_path, "f.txt", b"OLD-CONTENT-LONGER")
    jail.write_bytes_atomic("f.txt", b"NEW")
    assert (pathlib.Path(jail.root_path) / "f.txt").read_bytes() == b"NEW"
    leftovers = [p.name for p in pathlib.Path(jail.root_path).iterdir()
                 if p.name.startswith(".dharma_tmp_")]
    assert leftovers == []


def test_write_mode_preserved_despite_umask(jail):
    old = os.umask(0o077)
    try:
        jail.write_bytes_atomic("run.sh", b"#!/bin/sh\n", mode=0o755)
        jail.write_bytes_atomic("secret.txt", b"k", mode=0o600)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(pathlib.Path(jail.root_path) / "run.sh").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(pathlib.Path(jail.root_path) / "secret.txt").st_mode) == 0o600


@pytest.mark.parametrize("bad_mode", [0o4755, 0o2755, 0o1777])
def test_write_setuid_setgid_sticky_rejected(jail, bad_mode):
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic("f", b"x", mode=bad_mode)
    assert ei.value.errno_code == errno.EPERM


def test_write_creates_parents(jail):
    jail.write_bytes_atomic("x/y/z.txt", b"deep")
    assert (pathlib.Path(jail.root_path) / "x" / "y" / "z.txt").read_bytes() == b"deep"


def test_write_parent_is_file_rejected(jail):
    seed(jail.root_path, "f.txt", b"x")
    with pytest.raises(ConfinementViolation) as ei:
        jail.write_bytes_atomic("f.txt/g.txt", b"y")
    assert ei.value.errno_code == errno.ENOTDIR


def test_write_failure_cleans_tmp_and_keeps_destination(jail, monkeypatch):
    dst = seed(jail.root_path, "f.txt", b"PRECIOUS")

    def boom(fd, data):
        raise OSError(errno.EIO, "injected write failure")

    monkeypatch.setattr(cw_vfs.os, "write", boom)
    with pytest.raises(ConfinementViolation):
        jail.write_bytes_atomic("f.txt", b"half-written")
    monkeypatch.undo()
    assert dst.read_bytes() == b"PRECIOUS"
    leftovers = [p.name for p in pathlib.Path(jail.root_path).iterdir()
                 if p.name.startswith(".dharma_tmp_")]
    assert leftovers == []


# ---------------------------------------------------------------- witness verification

def _write_witness(jail):
    return jail.write_bytes_atomic("w.txt", b"payload-text")


def test_verify_witness_write_happy(jail):
    wit = _write_witness(jail)
    ok, why, triple = verify_witness_against_call(
        wit, "file_write", {"path": "w.txt", "content": "payload-text"}, {})
    assert ok, why
    assert triple == ("write", "w.txt", wit.content_sha256)
    ok, why, _ = verify_witness_against_call(
        wit, "file_write", {"path": "w.txt", "content": "payload-text"},
        {"content_sha256": wit.content_sha256})
    assert ok, why
    # A write witness is bound to the content the call says it wrote. A result
    # that carries the witness's hash does not vouch for different call content.
    ok, why, _ = verify_witness_against_call(
        wit, "file_write", {"path": "w.txt", "content": "tamper?"},
        {"content_sha256": wit.content_sha256})
    assert not ok and "does not match" in why, why
    ok, why, _ = verify_witness_against_call(
        wit, "file_write", {"path": "w.txt", "content": "tamper?"}, {})
    assert not ok and "content_sha256 mismatch" in why, why


def test_verify_witness_read_happy(jail):
    jail.write_bytes_atomic("w.txt", b"hello")
    data, _, wit = jail.read_bytes("w.txt")
    ok, why, _ = verify_witness_against_call(
        wit, "file_read", {"path": "w.txt"},
        {"content": "hello", "content_sha256": wit.content_sha256})
    assert ok, why
    # fallback branch: sha re-derived from content
    ok, _, _ = verify_witness_against_call(wit, "file_read", {"path": "w.txt"}, {"content": "hello"})
    assert ok


@pytest.mark.parametrize("field,value,reason", [
    ("confined", False, "not marked confined"),
    ("op", "read", "op mismatch"),
    ("requested_path", "/elsewhere", "requested_path mismatch"),
    ("content_sha256", "0" * 64, "content_sha256 mismatch"),
    ("resolve_flags", 0x0E, "weak resolve_flags"),
    ("leaf_nlink", 2, "leaf_nlink"),
    ("expected_hops", 99, "hop chain length"),
    ("hop_inodes", (1, 2), "hop chain"),
    ("leaf_ino", 999999, "hop chain endpoints"),
])
def test_verify_witness_tampered(jail, field, value, reason):
    wit = _write_witness(jail)
    bad = dataclasses.replace(wit, **{field: value})
    ok, why, _ = verify_witness_against_call(
        bad, "file_write", {"path": "w.txt", "content": "payload-text"}, {})
    assert not ok and reason in why, why


def test_verify_witness_non_positive_inode(jail):
    wit = _write_witness(jail)
    bad = dataclasses.replace(
        wit, rel_lexical_path="d/w.txt", expected_hops=3,
        hop_inodes=(wit.root_ino, 0, wit.leaf_ino))
    ok, why, _ = verify_witness_against_call(
        bad, "file_write", {"path": "w.txt", "content": "payload-text"}, {})
    assert not ok and "non-positive inode" in why, why


# ---------------------------------------------------------------- Coq emission

def test_coq_emission_structure(jail):
    wit = jail.write_bytes_atomic("d/f.txt", b"payload")
    defs, stmt = wit.coq_definitions_and_statement("vfs_0", "write", "d/f.txt", wit.content_sha256)
    assert len(defs) == 15  # leaf_mode is a definition and a conjunct
    assert f"Definition vfs_0_lmode : Z := {wit.leaf_mode}." in defs
    assert "Z.land vfs_0_lmode 3584 =? 0" in stmt  # no setuid, setgid or sticky bit
    assert "vfs_0_rdev =?" not in stmt  # D12: devices are recorded, not compared
    assert "Definition vfs_0_mask : Z := 15." in defs
    assert "Definition vfs_0_exp_hops : Z := 3." in defs  # components(d,f.txt)+1
    assert f"Definition vfs_0_rdev : Z := {wit.root_dev}." in defs
    hops_line = [l for l in defs if "_hops : list Z" in l][0]
    entries = hops_line[hops_line.index("[") + 1:hops_line.index("]")].split("; ")
    assert len(entries) == 3 and all(e.isdigit() for e in entries)
    assert "Z.land vfs_0_mask 15 =? 15" in stmt
    assert stmt.endswith("= true")
    assert stmt.count("(") == stmt.count(")")
    # a weakened witness is faithfully encoded (theorem then cannot close)
    weak = dataclasses.replace(wit, resolve_flags=0x0E)
    defs2, _ = weak.coq_definitions_and_statement("vfs_1", "write", "d/f.txt", weak.content_sha256)
    assert "Definition vfs_1_mask : Z := 14." in defs2


@pytest.mark.skipif(not COQC, reason="coqc not installed in this sandbox")
def test_coq_certificate_compiles_and_fails_closed(jail, tmp_path):
    wit = jail.write_bytes_atomic("d/f.txt", b"payload")
    defs, stmt = wit.coq_definitions_and_statement("vfs_t", "write", "d/f.txt", wit.content_sha256)

    def compile(defs, stmt):
        v = tmp_path / "cert.v"
        v.write_text(
            "Require Import ZArith List Bool.\nImport ListNotations.\nOpen Scope Z_scope.\n\n"
            + "\n".join(defs) + f"\n\nTheorem vfs_t : {stmt}.\nProof. vm_compute. reflexivity. Qed.\n")
        out = tmp_path / "cert.vo"
        return subprocess.run([COQC, "-o", str(out), str(v)],
                               capture_output=True, timeout=120).returncode

    assert compile(defs, stmt) == 0
    tampered = [l.replace(":= 15.", ":= 14.") if "_mask" in l else l for l in defs]
    assert compile(tampered, stmt) != 0  # weakened mask must not close the theorem


# ---------------------------------------------------------------- clone_confined_snapshot

def _mk_tree(root: pathlib.Path):
    (root / "a" / "b").mkdir(parents=True)
    (root / "emptydir").mkdir()
    (root / "a" / "f.bin").write_bytes(b"\x00\x01\x02")
    os.chmod(root / "a" / "f.bin", 0o600)
    (root / "run.sh").write_bytes(b"#!/bin/sh\n")
    os.chmod(root / "run.sh", 0o755)
    (root / "a" / "b" / "data.txt").write_bytes(b"hello")
    (root / "a" / "b" / "\u7b2c\u4e00\u9875.txt").write_bytes(b"\xe4\xb8\xad")
    (root / "a" / "b" / "empty.txt").write_bytes(b"")
    os.chmod(root / "a", 0o700)
    os.chmod(root / "a" / "b", 0o750)


def test_clone_basic(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _mk_tree(src)
    dst = tmp_path / "snap"
    info = clone_confined_snapshot(src, dst)
    assert info["copied_files"] == 5
    assert (dst / "a" / "f.bin").read_bytes() == b"\x00\x01\x02"
    assert (dst / "run.sh").read_bytes() == b"#!/bin/sh\n"
    assert (dst / "a" / "b" / "data.txt").read_bytes() == b"hello"
    assert (dst / "a" / "b" / "\u7b2c\u4e00\u9875.txt").read_bytes() == b"\xe4\xb8\xad"
    assert (dst / "a" / "b" / "empty.txt").read_bytes() == b""
    assert stat.S_IMODE(os.stat(dst / "a" / "f.bin").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(dst / "run.sh").st_mode) == 0o755


def test_clone_preserves_empty_dirs(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "emptydir").mkdir()
    (src / "a").mkdir()
    (src / "a" / "f.txt").write_bytes(b"x")
    dst = tmp_path / "snap"
    clone_confined_snapshot(src, dst)
    assert (dst / "emptydir").is_dir()  # D11b: must not be silently dropped
    assert (dst / "a" / "f.txt").read_bytes() == b"x"


def test_clone_preserves_directory_modes(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").mkdir()
    (src / "a" / "f.txt").write_bytes(b"x")
    os.chmod(src / "a", 0o700)
    dst = tmp_path / "snap"
    old = os.umask(0o022)
    try:
        clone_confined_snapshot(src, dst)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(dst / "a").st_mode) == 0o700  # D11a: no 0700 -> 0755 widening


def test_clone_no_fd_leak(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _mk_tree(src)
    before = fd_count()
    for i in range(3):
        clone_confined_snapshot(src, tmp_path / f"snap{i}")
    assert fd_count() - before < 5  # D11c: scandir(fd) keeps fds open; none may leak


def test_clone_rejects_symlink(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_bytes(b"x")
    os.symlink("f.txt", src / "sym")
    with pytest.raises(ConfinementViolation) as ei:
        clone_confined_snapshot(src, tmp_path / "snap")
    assert ei.value.errno_code == errno.ELOOP


def test_clone_rejects_hardlink(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_bytes(b"x")
    os.link(src / "f.txt", src / "g.txt")
    with pytest.raises(ConfinementViolation) as ei:
        clone_confined_snapshot(src, tmp_path / "snap")
    assert ei.value.errno_code == errno.EMLINK


def test_clone_rejects_oversize(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(b"x" * 11)
    with pytest.raises(ConfinementViolation) as ei:
        clone_confined_snapshot(src, tmp_path / "snap", max_file_bytes=10)
    assert ei.value.errno_code == errno.EFBIG


def test_clone_rejects_fifo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    os.mkfifo(src / "pipe")
    with pytest.raises(ConfinementViolation) as ei:
        clone_confined_snapshot(src, tmp_path / "snap")
    assert ei.value.errno_code == errno.EINVAL


# ---------------------------------------------------------------- mkdir_confined (D11a)

def test_mkdir_confined_mode(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    with CapabilityDirJail(root) as j:
        old = os.umask(0o022)
        try:
            j.mkdir_confined("s", 0o750)
            j.mkdir_confined("s/t", 0o700)
        finally:
            os.umask(old)
    assert stat.S_IMODE(os.stat(root / "s").st_mode) == 0o750
    assert stat.S_IMODE(os.stat(root / "s" / "t").st_mode) == 0o700


def test_mkdir_confined_idempotent(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    with CapabilityDirJail(root) as j:
        j.mkdir_confined("s", 0o750)
        j.mkdir_confined("s", 0o750)  # re-run on existing dir: no error, mode kept
    assert stat.S_IMODE(os.stat(root / "s").st_mode) == 0o750


def test_mkdir_confined_rejects_sticky(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    with CapabilityDirJail(root) as j:
        with pytest.raises(ConfinementViolation) as ei:
            j.mkdir_confined("s", 0o1777)
        assert ei.value.errno_code == errno.EPERM


def test_mkdir_confined_rejects_symlinked_existing(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    (root / "real").mkdir()
    os.symlink("real", root / "sym")
    with CapabilityDirJail(root) as j:
        with pytest.raises(ConfinementViolation) as ei:
            j.mkdir_confined("sym", 0o755)
        assert ei.value.errno_code in (errno.ELOOP, errno.ENOTDIR)


def test_mkdir_confined_walks_parents(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    with CapabilityDirJail(root) as j:
        j.mkdir_confined("p/q/r", 0o755)
    assert (root / "p" / "q" / "r").is_dir()
    assert stat.S_IMODE(os.stat(root / "p" / "q" / "r").st_mode) == 0o755
