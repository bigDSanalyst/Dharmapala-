import errno
import os
import tempfile
import unittest

from cw_vfs import (
    CapabilityDirJail,
    CapabilityWitness,
    ConfinementViolation,
    clone_confined_snapshot,
    verify_witness_against_call,
)
from tools import Sandbox
from to_coq_witness import build_certificate


class TestCWVFSConfinement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cw_vfs_test_")
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_d1_lexical_escape_and_symlink_collapse(self):
        outside = tempfile.NamedTemporaryFile(delete=False)
        outside.write(b"secret")
        outside.close()
        try:
            os.symlink(os.path.dirname(outside.name), os.path.join(self.root, "sym_dir"))
            with CapabilityDirJail(self.root) as jail:
                with self.assertRaises(ConfinementViolation) as ctx:
                    jail.read_bytes("../outside.txt")
                self.assertEqual(ctx.exception.errno_code, errno.EXDEV)

                with self.assertRaises(ConfinementViolation) as ctx2:
                    jail.read_bytes("sym_dir/../anything")
                self.assertEqual(ctx2.exception.errno_code, errno.ELOOP)

                with self.assertRaises(ConfinementViolation) as ctx3:
                    jail.read_bytes(os.path.join(self.root, "sub", "..", "file.txt"))
                self.assertEqual(ctx3.exception.errno_code, errno.EXDEV)
        finally:
            os.unlink(outside.name)

    def test_hardlink_and_fifo_rejection(self):
        target = os.path.join(self.root, "a.txt")
        hardlink = os.path.join(self.root, "b.txt")
        fifo = os.path.join(self.root, "pipe.fifo")
        with open(target, "wb") as f:
            f.write(b"data")
        os.link(target, hardlink)
        os.mkfifo(fifo)

        with CapabilityDirJail(self.root) as jail:
            with self.assertRaises(ConfinementViolation) as ctx:
                jail.read_bytes("a.txt")
            self.assertEqual(ctx.exception.errno_code, errno.EMLINK)

            with self.assertRaises(ConfinementViolation) as ctx_fifo:
                jail.read_bytes("pipe.fifo")
            self.assertEqual(ctx_fifo.exception.errno_code, errno.EINVAL)

    def test_d8_exact_truncation_and_d10_mode_bits(self):
        with CapabilityDirJail(self.root) as jail:
            with self.assertRaises(ConfinementViolation) as ctx:
                jail.write_bytes_atomic("suid.sh", b"echo hi", mode=0o4755)
            self.assertEqual(ctx.exception.errno_code, errno.EPERM)

            wit = jail.write_bytes_atomic("run.sh", b"#!/bin/sh\necho ok\n", mode=0o755)
            self.assertEqual(wit.leaf_mode, 0o755)

            jail.write_bytes_atomic("ten.txt", b"0123456789")
            data, trunc, _ = jail.read_bytes("ten.txt", max_bytes=10)
            self.assertFalse(trunc)
            self.assertEqual(data, b"0123456789")

            jail.write_bytes_atomic("eleven.txt", b"0123456789X")
            data2, trunc2, _ = jail.read_bytes("eleven.txt", max_bytes=10)
            self.assertTrue(trunc2)
            self.assertEqual(data2, b"0123456789")

    def test_sandbox_tamper_binding_and_coq_emission(self):
        sb = Sandbox(self.root)
        try:
            wres = sb.file_write("nested/hello.txt", "dharma-vow")
            self.assertTrue(wres["ok"])
            rres = sb.file_read("nested/hello.txt")
            self.assertTrue(rres["ok"])
            self.assertEqual(rres["content"], "dharma-vow")
        finally:
            sb.close()

        tool, kwargs, result = sb.calls[1]
        wit = CapabilityWitness.from_dict(result["capability_witness"])
        ok, why, _ = verify_witness_against_call(wit, tool, kwargs, result)
        self.assertTrue(ok, why)

        tampered_result = dict(result, content="forged-content")
        ok_bad, why_bad, _ = verify_witness_against_call(wit, tool, kwargs, tampered_result)
        self.assertFalse(ok_bad)
        self.assertIn("content_sha256", why_bad)

        evidence = {"workdir": self.root, "calls": sb.calls}
        cert = build_certificate("test_cert", {"butterflies": []}, evidence=evidence)
        self.assertEqual(len(cert.witnesses), 2)
        self.assertIn("hd 0 (rev vfs_0_hops) =? vfs_0_lino", cert.witnesses[0].statement)


if __name__ == "__main__":
    unittest.main()
