"""Capability-Witnessed VFS Confinement (CW-VFS, Hardened D1-D12).

Eliminates ambient-authority userspace path resolution across Sandbox file tools,
rehearsal snapshots (critic_loop.py), and co-signer replays (replay.py) via:
  1. Kernel-atomic descriptor pinning with Linux SYS_openat2 (0x0F strict resolve).
  2. Regular-file exclusivity (S_ISREG, st_nlink == 1) + dcache anti-race checks.
  3. Action-bound CapabilityWitness emission compiled into Coq vm_compute theorems.

Cross-mount confinement is RESOLVE_NO_XDEV's, enforced by the kernel on every
openat2 (D12). Device numbers are recorded, never compared: overlay and
passthrough filesystems give inodes of one mount different st_dev values.
"""
from __future__ import annotations
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass

_ARCH_SYS_OPENAT2 = {"x86_64": 437, "aarch64": 437, "arm64": 437, "riscv64": 437}

RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE_STRICT_MASK = (
    RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
)
_FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


try:
    _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    _LIBC.syscall.restype = ctypes.c_long
except OSError:
    _LIBC = None

_SYS_NR = _ARCH_SYS_OPENAT2.get(os.uname().machine) if hasattr(os, "uname") else None


class ConfinementViolation(PermissionError):
    def __init__(self, msg: str, errno_code: int = errno.EACCES):
        super().__init__(msg)
        self.errno_code = errno_code


def _sys_openat2(dirfd: int, rel_bytes: bytes, flags: int, mode: int, resolve: int) -> int:
    if _LIBC is None or _SYS_NR is None:
        raise ConfinementViolation("platform lacks Linux SYS_openat2", errno.ENOSYS)
    how = _OpenHow(flags=flags, mode=mode, resolve=resolve)
    fd = _LIBC.syscall(
        ctypes.c_long(_SYS_NR),
        ctypes.c_int(dirfd),
        ctypes.c_char_p(rel_bytes),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(_OpenHow)),
    )
    if fd < 0:
        err = ctypes.get_errno()
        if err == errno.ENOSYS:
            raise ConfinementViolation("kernel lacks SYS_openat2 (< Linux 5.6)", errno.ENOSYS)
        raise OSError(err, os.strerror(err), rel_bytes.decode("utf-8", "replace"))
    return int(fd)


@dataclass(frozen=True)
class CapabilityWitness:
    op: str
    requested_path: str
    rel_lexical_path: str
    expected_hops: int
    root_dev: int
    root_ino: int
    hop_inodes: tuple[int, ...]
    leaf_dev: int
    leaf_ino: int
    leaf_nlink: int
    leaf_mode: int
    truncated: bool
    fd_realpath: str
    resolve_flags: int
    content_sha256: str
    confined: bool

    def to_dict(self) -> dict:
        d = asdict(self)
        d["hop_inodes"] = list(self.hop_inodes)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityWitness":
        data = dict(d)
        data["hop_inodes"] = tuple(int(x) for x in data["hop_inodes"])
        return cls(**data)

    def coq_definitions_and_statement(
        self,
        prefix: str,
        expected_op: str,
        expected_rel_path: str,
        expected_content_sha256: str,
    ) -> tuple[list[str], str]:
        op_map = {"read": 1, "write": 2}
        wit_op = op_map.get(self.op, 0)
        exp_op = op_map.get(expected_op, -1)
        wit_path_z = int(hashlib.sha256(self.rel_lexical_path.encode("utf-8")).hexdigest(), 16)
        exp_path_z = int(hashlib.sha256(expected_rel_path.encode("utf-8")).hexdigest(), 16)
        exp_hops = len([s for s in expected_rel_path.split("/") if s and s != "."]) + 1
        wit_content_z = int(self.content_sha256, 16)
        exp_content_z = int(expected_content_sha256, 16)
        hops_coq = "; ".join(str(x) for x in self.hop_inodes)
        defs = [
            f"Definition {prefix}_wit_op : Z := {wit_op}.",
            f"Definition {prefix}_exp_op : Z := {exp_op}.",
            f"Definition {prefix}_wit_path : Z := {wit_path_z}.",
            f"Definition {prefix}_exp_path : Z := {exp_path_z}.",
            f"Definition {prefix}_wit_sha : Z := {wit_content_z}.",
            f"Definition {prefix}_exp_sha : Z := {exp_content_z}.",
            f"Definition {prefix}_exp_hops : Z := {exp_hops}.",
            f"Definition {prefix}_rdev : Z := {self.root_dev}.",
            f"Definition {prefix}_ldev : Z := {self.leaf_dev}.",
            f"Definition {prefix}_rino : Z := {self.root_ino}.",
            f"Definition {prefix}_lino : Z := {self.leaf_ino}.",
            f"Definition {prefix}_nlink : Z := {self.leaf_nlink}.",
            f"Definition {prefix}_lmode : Z := {self.leaf_mode}.",
            f"Definition {prefix}_mask : Z := {self.resolve_flags}.",
            f"Definition {prefix}_hops : list Z := [{hops_coq}].",
        ]
        stmt = (
            f"(({prefix}_wit_op =? 1) || ({prefix}_wit_op =? 2)) && "
            f"({prefix}_wit_op =? {prefix}_exp_op) && "
            f"({prefix}_wit_path =? {prefix}_exp_path) && "
            f"({prefix}_wit_sha =? {prefix}_exp_sha) && "
            f"(Z.land {prefix}_mask 15 =? 15) && "
            f"(Z.land {prefix}_lmode 3584 =? 0) && "
            f"({prefix}_nlink =? 1) && "
            f"(Z.of_nat (length {prefix}_hops) =? {prefix}_exp_hops) && "
            f"(forallb (fun i => 0 <? i) {prefix}_hops) && "
            f"(hd 0 {prefix}_hops =? {prefix}_rino) && "
            f"(hd 0 (rev {prefix}_hops) =? {prefix}_lino) = true"
        )
        return defs, stmt


class CapabilityDirJail:
    RESOLVE_STRICT = RESOLVE_STRICT_MASK

    def __init__(self, workdir: str | os.PathLike, logical_workdir: str | None = None):
        self._root_fd = -1
        self.root_path = os.path.realpath(os.fspath(workdir))
        self.logical_root = (
            os.path.realpath(os.fspath(logical_workdir))
            if logical_workdir is not None
            else self.root_path
        )
        os.makedirs(self.root_path, exist_ok=True)
        fd = os.open(
            self.root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_nlink < 1:
                raise ConfinementViolation("workspace root invalid or unlinked", errno.ENOENT)
            self.root_dev, self.root_ino = st.st_dev, st.st_ino
            self._root_fd = fd
        except Exception:
            os.close(fd)
            raise
        self.resolve_mask = self.RESOLVE_STRICT

    def close(self) -> None:
        fd = getattr(self, "_root_fd", -1)
        if fd >= 0:
            self._root_fd = -1
            try:
                os.close(fd)
            except OSError:
                pass

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "CapabilityDirJail":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _resolve_safe_parts(self, raw_path: str) -> list[str]:
        """Fix D1 + benign relative '..' compatibility:
        - Absolute paths MUST NOT contain '..' before literal root prefix stripping.
        - Relative paths containing '..' are checked component-by-component against
          the live directory descriptor so symlinks (S_ISLNK) are rejected with ELOOP
          before '..' can ever pop a segment, and escaping root raises EXDEV.
        """
        if not isinstance(raw_path, str) or "\x00" in raw_path or not raw_path.strip():
            raise ConfinementViolation(f"invalid path: {raw_path!r}", errno.EINVAL)
        raw_segs = raw_path.split("/")
        if os.path.isabs(raw_path):
            if any(seg == ".." for seg in raw_segs):
                raise ConfinementViolation(
                    f"'..' traversal forbidden in absolute path {raw_path!r}", errno.EXDEV
                )
            clean = [s for s in raw_segs if s and s != "."]
            for allowed_root in (self.root_path, self.logical_root):
                rsegs = [s for s in allowed_root.split("/") if s and s != "."]
                if len(clean) > len(rsegs) and clean[: len(rsegs)] == rsegs:
                    return clean[len(rsegs):]
                if clean == rsegs:
                    raise ConfinementViolation("cannot read/write workspace root", errno.EISDIR)
            raise ConfinementViolation(
                f"absolute path {raw_path!r} escapes jailed workdir {self.logical_root!r}",
                errno.EXDEV,
            )

        # Relative path: verify every segment pushed before '..' is NOT a symlink on disk!
        stack: list[str] = []
        for seg in raw_segs:
            if not seg or seg == ".":
                continue
            if seg == "..":
                if not stack:
                    raise ConfinementViolation(f"{raw_path!r} escapes workdir via '..'", errno.EXDEV)
                # Probe current stack prefix via openat2 / fstatat to forbid 'symlink_out/..' collapse!
                self._assert_prefix_has_no_symlink(stack)
                stack.pop()
            else:
                if len(seg.encode("utf-8")) > 255:
                    raise ConfinementViolation("segment exceeds NAME_MAX", errno.ENAMETOOLONG)
                stack.append(seg)
        if not stack:
            raise ConfinementViolation(f"empty relative path {raw_path!r}", errno.EINVAL)
        return stack

    def _assert_prefix_has_no_symlink(self, prefix_parts: list[str]) -> None:
        cur_fd = os.dup(self._root_fd)
        try:
            for seg in prefix_parts:
                try:
                    st = os.stat(seg, dir_fd=cur_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return  # Non-existent directory inside confirmed in-jail parent is not a symlink
                if stat.S_ISLNK(st.st_mode):
                    raise ConfinementViolation(
                        f"symlink component {seg!r} forbidden before '..'", errno.ELOOP
                    )
                if not stat.S_ISDIR(st.st_mode):
                    raise ConfinementViolation(
                        f"non-directory component {seg!r} before '..'", errno.ENOTDIR
                    )
                nxt_fd = _sys_openat2(
                    cur_fd,
                    seg.encode("utf-8"),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0,
                    self.resolve_mask,
                )
                os.close(cur_fd)
                cur_fd = nxt_fd
        finally:
            os.close(cur_fd)

    def _walk_parent_hops(self, parts: list[str], create_dirs: bool) -> tuple[int, list[int]]:
        cur_fd = os.dup(self._root_fd)
        hops = [self.root_ino]
        try:
            for seg in parts:
                if len(seg.encode("utf-8")) > 255:
                    raise ConfinementViolation("directory segment exceeds NAME_MAX", errno.ENAMETOOLONG)
                if create_dirs:
                    try:
                        os.mkdir(seg, mode=0o755, dir_fd=cur_fd)
                    except FileExistsError:
                        pass
                nxt_fd = _sys_openat2(
                    cur_fd,
                    seg.encode("utf-8"),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0,
                    self.resolve_mask,
                )
                st = os.fstat(nxt_fd)
                # D12: no st_dev comparison; RESOLVE_NO_XDEV refused any mount crossing.
                if not stat.S_ISDIR(st.st_mode) or st.st_nlink < 1 or st.st_ino <= 0:
                    os.close(nxt_fd)
                    raise ConfinementViolation("directory hop is not a live directory", errno.ENOENT)
                hops.append(st.st_ino)
                os.close(cur_fd)
                cur_fd = nxt_fd
            return cur_fd, hops
        except Exception as e:
            os.close(cur_fd)
            if isinstance(e, ConfinementViolation):
                raise
            if isinstance(e, OSError):
                raise ConfinementViolation(
                    f"hop walk blocked {parts!r}: {e.strerror}", e.errno or errno.EACCES
                )
            raise

    def _verify_live_regular_fd(
        self, fd: int, parent_fd: int, base_name: str
    ) -> tuple[os.stat_result, str]:
        st = os.fstat(fd)
        # D12: no st_dev comparison with the root; RESOLVE_NO_XDEV kept the open on its mount.
        if not stat.S_ISREG(st.st_mode):
            raise ConfinementViolation(f"refusing non-regular file mode={oct(st.st_mode)}", errno.EINVAL)
        if st.st_nlink != 1:
            code = errno.ENOENT if st.st_nlink < 1 else errno.EMLINK
            raise ConfinementViolation(
                f"refusing unlinked or hardlinked regular file (st_nlink={st.st_nlink})", code
            )
        try:
            pst = os.stat(base_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as e:
            raise ConfinementViolation(f"entry vanished during race: {e.strerror}", errno.ENOENT)
        if pst.st_dev != st.st_dev or pst.st_ino != st.st_ino or pst.st_nlink != 1:
            code = errno.EMLINK if pst.st_nlink > 1 else errno.EXDEV
            raise ConfinementViolation("concurrent dentry swap or hardlink detected", code)
        fd_real = os.readlink(f"/proc/self/fd/{fd}")
        prefix = self.root_path.rstrip("/") + "/"
        if fd_real.endswith(" (deleted)") or not (
            fd_real == self.root_path or fd_real.startswith(prefix)
        ):
            raise ConfinementViolation(f"dcache path {fd_real!r} invalid", errno.EXDEV)
        return st, fd_real

    def mkdir_confined(self, raw_path: str, mode: int = 0o755) -> None:
        """Fix D11a: idempotently create a directory inside the jail with the
        exact 0o777 mode (umask-defeating fchmod), refusing setuid/setgid/sticky
        bits, symlinked components, and non-directory hops along the way.
        Creation starts narrow (0700) and is widened only after openat2 has
        re-pinned the directory inside the jail."""
        if mode & _FORBIDDEN_MODE_BITS:
            raise ConfinementViolation("setuid/setgid/sticky mode bits forbidden", errno.EPERM)
        safe_mode = mode & 0o777
        parts = self._resolve_safe_parts(raw_path)
        if len(parts[-1].encode("utf-8")) > 255:
            raise ConfinementViolation("directory name exceeds NAME_MAX", errno.ENAMETOOLONG)
        parent_fd, _hops = self._walk_parent_hops(parts[:-1], create_dirs=True)
        fd = -1
        try:
            try:
                os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            except OSError as e:
                raise ConfinementViolation(
                    f"mkdir_confined blocked {raw_path!r}: {e.strerror}", e.errno or errno.EACCES
                )
            try:
                fd = _sys_openat2(
                    parent_fd,
                    parts[-1].encode("utf-8"),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0,
                    self.resolve_mask,
                )
            except OSError as e:
                raise ConfinementViolation(
                    f"mkdir_confined pin blocked {raw_path!r}: {e.strerror}", e.errno or errno.EACCES
                )
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_nlink < 1:
                raise ConfinementViolation(
                    f"mkdir_confined pinned non-directory {raw_path!r}", errno.ENOTDIR
                )
            os.fchmod(fd, safe_mode)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    def read_bytes(
        self, raw_path: str, max_bytes: int = 2000
    ) -> tuple[bytes, bool, CapabilityWitness]:
        parts = self._resolve_safe_parts(raw_path)
        if len(parts[-1].encode("utf-8")) > 255:
            raise ConfinementViolation("filename exceeds NAME_MAX", errno.ENAMETOOLONG)
        parent_fd, hops = self._walk_parent_hops(parts[:-1], create_dirs=False)
        fd = -1
        try:
            try:
                fd = _sys_openat2(
                    parent_fd,
                    parts[-1].encode("utf-8"),
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                    0,
                    self.resolve_mask,
                )
            except OSError as e:
                raise ConfinementViolation(
                    f"openat2 blocked {raw_path!r}: {e.strerror}", e.errno or errno.EACCES
                )
            st, _ = self._verify_live_regular_fd(fd, parent_fd, parts[-1])
            # Fix D9: clear O_NONBLOCK now that S_ISREG is proven so FUSE/overlayfs reads never EAGAIN
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

            # Fix D8: read up to max_bytes + 1 to detect exact truncation
            chunks, rem = [], max_bytes + 1
            while rem > 0:
                try:
                    buf = os.read(fd, rem)
                except InterruptedError:
                    continue
                if not buf:
                    break
                chunks.append(buf)
                rem -= len(buf)
            st_after, fd_real = self._verify_live_regular_fd(fd, parent_fd, parts[-1])
            if st_after.st_ino != st.st_ino:
                raise ConfinementViolation("mid-read inode swap detected", errno.EXDEV)
            raw_all = b"".join(chunks)
            truncated = len(raw_all) > max_bytes
            data = raw_all[:max_bytes]
            full_hops = tuple(hops + [st.st_ino])
            return data, truncated, CapabilityWitness(
                op="read",
                requested_path=raw_path,
                rel_lexical_path="/".join(parts),
                expected_hops=len(parts) + 1,
                root_dev=self.root_dev,
                root_ino=self.root_ino,
                hop_inodes=full_hops,
                leaf_dev=st.st_dev,
                leaf_ino=st.st_ino,
                leaf_nlink=st_after.st_nlink,
                leaf_mode=st_after.st_mode & 0o777,
                truncated=truncated,
                fd_realpath=fd_real,
                resolve_flags=self.resolve_mask,
                content_sha256=hashlib.sha256(data).hexdigest(),
                confined=True,
            )
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    def write_bytes_atomic(
        self, raw_path: str, data: bytes, mode: int = 0o644
    ) -> CapabilityWitness:
        # Fix D10: preserve safe permission bits (e.g., 0o755 scripts) while forbidding setuid/setgid
        if mode & _FORBIDDEN_MODE_BITS:
            raise ConfinementViolation("setuid/setgid/sticky mode bits forbidden", errno.EPERM)
        safe_mode = mode & 0o777
        parts = self._resolve_safe_parts(raw_path)
        base = parts[-1]
        if len(base.encode("utf-8")) > 255:
            raise ConfinementViolation("filename exceeds NAME_MAX", errno.ENAMETOOLONG)
        parent_fd, hops = self._walk_parent_hops(parts[:-1], create_dirs=True)
        tmp_name = f".dharma_tmp_{os.urandom(12).hex()}"
        fd = -1
        tmp_created = False
        replaced_with_ino = None
        try:
            try:
                dst_st = os.stat(base, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(dst_st.st_mode):
                    raise ConfinementViolation(f"destination {raw_path!r} is a symlink", errno.ELOOP)
                if stat.S_ISDIR(dst_st.st_mode):
                    raise ConfinementViolation(f"destination {raw_path!r} is a directory", errno.EISDIR)
                if not stat.S_ISREG(dst_st.st_mode):
                    raise ConfinementViolation(f"destination {raw_path!r} is non-regular", errno.EINVAL)
                if dst_st.st_nlink != 1:
                    raise ConfinementViolation(
                        f"destination {raw_path!r} is hardlinked (nlink={dst_st.st_nlink})",
                        errno.EMLINK,
                    )
            except FileNotFoundError:
                pass
            fd = _sys_openat2(
                parent_fd,
                tmp_name.encode("utf-8"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                safe_mode,
                self.resolve_mask,
            )
            tmp_created = True
            os.fchmod(fd, safe_mode)
            view, written = memoryview(data), 0
            while written < len(data):
                written += os.write(fd, view[written:])
            os.fsync(fd)
            st_tmp = os.fstat(fd)
            if st_tmp.st_nlink != 1:
                raise ConfinementViolation("staging inode hardlinked mid-write", errno.EMLINK)
            os.close(fd)
            fd = -1
            os.replace(tmp_name, base, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
            tmp_created = False
            replaced_with_ino = st_tmp.st_ino

            vfd = _sys_openat2(
                parent_fd,
                base.encode("utf-8"),
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                0,
                self.resolve_mask,
            )
            try:
                vst, fd_real = self._verify_live_regular_fd(vfd, parent_fd, base)
                if vst.st_ino != st_tmp.st_ino or vst.st_dev != st_tmp.st_dev:
                    raise ConfinementViolation("post-replace inode mismatch", errno.EXDEV)
            finally:
                os.close(vfd)
            full_hops = tuple(hops + [vst.st_ino])
            return CapabilityWitness(
                op="write",
                requested_path=raw_path,
                rel_lexical_path="/".join(parts),
                expected_hops=len(parts) + 1,
                root_dev=self.root_dev,
                root_ino=self.root_ino,
                hop_inodes=full_hops,
                leaf_dev=vst.st_dev,
                leaf_ino=vst.st_ino,
                leaf_nlink=vst.st_nlink,
                leaf_mode=vst.st_mode & 0o777,
                truncated=False,
                fd_realpath=fd_real,
                resolve_flags=self.resolve_mask,
                content_sha256=hashlib.sha256(data).hexdigest(),
                confined=True,
            )
        except Exception as e:
            if fd >= 0:
                os.close(fd)
            if tmp_created:
                try:
                    os.unlink(tmp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            elif replaced_with_ino is not None:
                try:
                    cur_st = os.stat(base, dir_fd=parent_fd, follow_symlinks=False)
                    if cur_st.st_ino == replaced_with_ino and cur_st.st_nlink == 1:
                        os.unlink(base, dir_fd=parent_fd)
                except OSError:
                    pass
            if isinstance(e, ConfinementViolation):
                raise
            if isinstance(e, OSError):
                raise ConfinementViolation(
                    f"jailed write blocked {raw_path!r}: {e.strerror}", e.errno or errno.EACCES
                )
            raise
        finally:
            os.close(parent_fd)


def clone_confined_snapshot(
    src_workdir: str | os.PathLike,
    dst_workdir: str | os.PathLike,
    max_file_bytes: int = 32 * 1024 * 1024,
) -> dict:
    with CapabilityDirJail(src_workdir) as src_jail, CapabilityDirJail(dst_workdir) as dst_jail:
        dirs: list[tuple[str, int]] = []
        files: list[tuple[str, os.stat_result]] = []

        def _scan(cur_fd: int) -> list[str]:
            # Fix D11c: os.scandir(fd) KEEPS the caller's fd open (verified on
            # Linux/CPython), so every fd handed to it must be a private dup,
            # released exactly once under either scandir ownership behavior.
            scan_fd = os.dup(cur_fd)
            try:
                with os.scandir(scan_fd) as it:
                    return [e.name for e in it]
            finally:
                try:
                    os.close(scan_fd)
                except OSError:
                    pass

        def _collect(rel_prefix: str, cur_src_fd: int) -> None:
            for name in _scan(cur_src_fd):
                if name.startswith(".dharma_tmp_"):
                    continue                  # an atomic write in progress, not the workdir's content
                rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
                st = os.stat(name, dir_fd=cur_src_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    raise ConfinementViolation(f"snapshot rejected symlink: {rel_path!r}", errno.ELOOP)
                if stat.S_ISDIR(st.st_mode):
                    dirs.append((rel_path, st.st_mode & 0o777))
                    sub_fd = _sys_openat2(
                        cur_src_fd,
                        name.encode("utf-8"),
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0,
                        src_jail.resolve_mask,
                    )
                    try:
                        _collect(rel_path, sub_fd)
                    finally:
                        os.close(sub_fd)
                elif stat.S_ISREG(st.st_mode):
                    if st.st_nlink != 1:
                        raise ConfinementViolation(
                            f"snapshot rejected hardlink (nlink={st.st_nlink}): {rel_path!r}",
                            errno.EMLINK,
                        )
                    if st.st_size > max_file_bytes:
                        raise ConfinementViolation(
                            f"snapshot file exceeds max_file_bytes: {rel_path!r}", errno.EFBIG
                        )
                    files.append((rel_path, st))
                else:
                    raise ConfinementViolation(
                        f"snapshot rejected non-regular entry: {rel_path!r}", errno.EINVAL
                    )

        root_scan_fd = os.dup(src_jail._root_fd)
        try:
            _collect("", root_scan_fd)
        finally:
            try:
                os.close(root_scan_fd)
            except OSError:
                pass

        # Fix D11a/D11b: create the directory skeleton FIRST so (a) each source
        # directory's exact 0o777 mode is preserved (umask-defeating fchmod)
        # instead of widening 0700 -> 0755, and (b) empty directories survive
        # the snapshot instead of being silently dropped (rehearsal/replay
        # fidelity: a real run may create them and the clone must match).
        for rel, mode in dirs:
            dst_jail.mkdir_confined(rel, mode)

        copied_files = 0
        for rel, st in files:
            data, truncated, _ = src_jail.read_bytes(rel, max_bytes=max_file_bytes)
            # Fix D8: fail closed on any concurrent file growth or partial read
            if truncated or len(data) != st.st_size:
                raise ConfinementViolation(
                    f"concurrent file size mutation during snapshot clone: {rel!r}",
                    errno.EIO,
                )
            # Fix D10: preserve exact 0o777 mode bits (e.g. executable scripts)
            dst_jail.write_bytes_atomic(rel, data, mode=(st.st_mode & 0o777))
            copied_files += 1
        return {"copied_files": copied_files, "root_ino": dst_jail.root_ino}


def verify_witness_against_call(
    witness: CapabilityWitness,
    tool: str,
    kwargs: dict,
    result: dict,
) -> tuple[bool, str, tuple[str, str, str]]:
    expected_op = "read" if tool == "file_read" else "write"
    raw_body = result.get("content", "") if tool == "file_read" else kwargs.get("content", "")
    if not isinstance(raw_body, str):
        return False, "content payload is not a string", ("", "", "")
    expected_sha = hashlib.sha256(raw_body.encode("utf-8")).hexdigest()
    rec_sha = result.get("content_sha256")
    if rec_sha is not None and rec_sha != expected_sha:
        return False, "result content_sha256 does not match actual content", ("", "", "")
    if not witness.confined:
        return False, "witness not marked confined", ("", "", "")
    if witness.op != expected_op:
        return False, f"op mismatch: {witness.op!r} != {expected_op!r}", ("", "", "")
    if witness.requested_path != str(kwargs.get("path", "")):
        return False, "requested_path mismatch against call kwargs", ("", "", "")
    if witness.content_sha256 != expected_sha:
        return False, "content_sha256 mismatch", ("", "", "")
    # D12: root_dev and leaf_dev are recorded, not compared; RESOLVE_NO_XDEV,
    # checked below, is what kept the open on the workdir's mount.
    if witness.resolve_flags != RESOLVE_STRICT_MASK:
        return False, f"weak resolve_flags={witness.resolve_flags}", ("", "", "")
    if witness.leaf_nlink != 1:
        return False, f"hardlink or unlinked leaf_nlink={witness.leaf_nlink}", ("", "", "")
    if witness.leaf_mode < 0 or witness.leaf_mode > 0o777 or (witness.leaf_mode & _FORBIDDEN_MODE_BITS):
        return False, f"forbidden leaf_mode={oct(witness.leaf_mode)}", ("", "", "")
    segs = witness.rel_lexical_path.split("/")
    if not witness.rel_lexical_path or any(s in ("", ".", "..") for s in segs):
        return False, f"non-canonical rel_lexical_path={witness.rel_lexical_path!r}", ("", "", "")
    depth = len(segs)
    if witness.expected_hops != depth + 1 or len(witness.hop_inodes) != depth + 1:
        return False, "hop chain length mismatch", ("", "", "")
    if witness.hop_inodes[0] != witness.root_ino or witness.hop_inodes[-1] != witness.leaf_ino:
        return False, "hop chain endpoints mismatch", ("", "", "")
    if any(i <= 0 for i in witness.hop_inodes):
        return False, "non-positive inode in hop chain", ("", "", "")
    return True, "ok", (expected_op, witness.rel_lexical_path, expected_sha)
