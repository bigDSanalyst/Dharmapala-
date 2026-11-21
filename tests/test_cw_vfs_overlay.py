"""CW-VFS on a real overlay filesystem (D12).

An overlay whose lower layer is another filesystem, mounted without xino,
reports one device for its directories and another for the files that come
from the lower layer. (With xino, which newer kernels turn on by themselves,
the overlay folds the layers' inode numbers into one space and reports its own
device for everything; GitHub's runners do that. A host whose overlays are
mounted without it, or whose kernel cannot do it, shows the split.) A jail that compared device
numbers refused every read, write and snapshot there. This builds such an
overlay itself (a tmpfs under an overlay), so it needs root to mount; CI runs
it as root with DHARMA_REQUIRE_OVERLAY=1, which turns a skip into a failure."""
import os
import stat
import subprocess

import pytest

import tests.support  # noqa: F401
from cw_vfs import CapabilityDirJail, clone_confined_snapshot

REQUIRED = os.environ.get("DHARMA_REQUIRE_OVERLAY") == "1"


def _cannot(why):
    if REQUIRED: pytest.fail(why)
    pytest.skip(why)


def _mount(*args):
    return subprocess.run(["mount", *args], capture_output=True, text=True)


@pytest.fixture
def overlay(tmp_path):
    lower, upper, work, merged = (tmp_path / n for n in ("lower", "upper", "work", "merged"))
    for d in (lower, upper, work, merged): d.mkdir()
    if os.geteuid() != 0:
        _cannot("mounting an overlay needs root")
    r = _mount("-t", "tmpfs", "tmpfs", str(lower))
    if r.returncode != 0:
        _cannot(f"cannot mount a tmpfs: {r.stderr.strip()}")
    try:
        w = lower / "w"
        (w / "sub").mkdir(parents=True); (w / "empty").mkdir()
        (w / "sub" / "f.txt").write_text("hello\n")
        (w / "run.sh").write_text("#!/bin/sh\n"); os.chmod(w / "run.sh", 0o755)
        opts = f"lowerdir={lower},upperdir={upper},workdir={work}"
        r = _mount("-t", "overlay", "overlay", "-o", opts + ",xino=off", str(merged))
        if r.returncode != 0:                      # a kernel too old to know xino has no xino
            r = _mount("-t", "overlay", "overlay", "-o", opts, str(merged))
        if r.returncode != 0:
            _cannot(f"cannot mount an overlay: {r.stderr.strip()}")
        try:
            yield merged / "w"
        finally:
            subprocess.run(["umount", str(merged)], check=False)
    finally:
        subprocess.run(["umount", str(lower)], check=False)


def test_the_overlay_reports_devices_per_inode(overlay):
    """The premise: without it the tests below would prove nothing."""
    assert os.stat(overlay).st_dev != os.stat(overlay / "sub" / "f.txt").st_dev


def test_reads_and_writes_work_on_the_overlay(overlay):
    with CapabilityDirJail(overlay) as j:
        data, _, w = j.read_bytes("sub/f.txt")
        assert data == b"hello\n" and w.leaf_dev != w.root_dev
        j.write_bytes_atomic("sub/new.txt", b"x")
        assert j.read_bytes("sub/new.txt")[0] == b"x"


def test_a_snapshot_of_an_overlay_workdir_is_complete(overlay, tmp_path):
    clone_confined_snapshot(overlay, tmp_path / "copy")
    c = tmp_path / "copy"
    assert (c / "sub" / "f.txt").read_text() == "hello\n"
    assert (c / "empty").is_dir()
    assert stat.S_IMODE(os.stat(c / "run.sh").st_mode) == 0o755
