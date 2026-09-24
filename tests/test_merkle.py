import hashlib

import pytest

import tests.support  # noqa: F401
import merkle
from mirror import Adversary, Class

def rfc6962_root(items):
    # An independent route to the same answer: RFC 6962 section 2.1, written
    # recursively, sharing no code with merkle.py.
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + items[0].encode()).digest()
    k = 1
    while k * 2 < len(items): k *= 2
    return hashlib.sha256(b"\x01" + rfc6962_root(items[:k]) + rfc6962_root(items[k:])).digest()

@pytest.mark.parametrize("n", range(1, 34))
def test_every_leaf_proves_membership(n):
    items = [f"class-{i}" for i in range(n)]; root = merkle.root(items)
    assert root == rfc6962_root(items).hex()
    for i, x in enumerate(items):
        proof = merkle.path(items, i)
        assert merkle.verify(x, proof, root)
        assert not merkle.verify(x + "!", proof, root)
        if proof:
            flipped = ((proof[0][0], "R" if proof[0][1] == "L" else "L"),) + proof[1:]
            assert not merkle.verify(x, flipped, root)

def test_a_proof_does_not_transfer_to_another_leaf():
    items = ["a", "b", "c", "d", "e"]; root = merkle.root(items)
    assert not merkle.verify("b", merkle.path(items, 0), root)

def test_transcript_paths_survive_classes_added_after_commitment():
    adv = Adversary("A", _NullSigner(), b"s")
    for cid in ("c.a", "c.b", "c.c"):
        adv.register(Class(cid, "forbid exfiltrate", 1.0), lambda s, c: {"effects": []})
    adv.commit()
    adv._classes.append(Class("c.a:shoshin-0000", "c.a", 10.0))   # what _select does
    adv._select = lambda guard, beacon, guard_nonce=b"": adv._classes[1]
    eng = adv.next_engagement(_Guard(), b"\x00" * 32, 0)
    assert eng.class_id == "c.b"
    assert merkle.verify(eng.class_id, eng.record.class_path,
                         adv.commitment.class_index_root)

class _NullSigner:
    id = "A"
    def sign(self, payload): return b"\x00"

class _Guard:
    id = "G"; current_hash = "0" * 64
    class ledger: records = []; audits = []
