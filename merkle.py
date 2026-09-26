
# One Merkle tree for the whole framework. Leaves and interior nodes are
# hashed under different prefixes (RFC 6962 section 2.1) so an interior node
# can never be presented as a leaf. An odd node at the end of a level is
# carried up unchanged, which gives the same tree shape as RFC 6962.
# A proof lists each sibling with the side it sits on; verification follows
# those sides, so building and checking cannot disagree about order.
import hashlib

EMPTY_ROOT = "0" * 64

def leaf_hash(item):
    return hashlib.sha256(b"\x00" + item.encode()).hexdigest()

def node_hash(left, right):
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

def _levels(items):
    layer = [leaf_hash(x) for x in items]; levels = [layer]
    while len(layer) > 1:
        nxt = [node_hash(layer[i], layer[i+1]) for i in range(0, len(layer) - 1, 2)]
        if len(layer) % 2: nxt.append(layer[-1])
        layer = nxt; levels.append(layer)
    return levels

def root(items):
    return _levels(items)[-1][0] if items else EMPTY_ROOT

def path(items, index):
    if not 0 <= index < len(items): raise IndexError(f"leaf {index} not in tree of {len(items)}")
    proof = []
    for layer in _levels(items)[:-1]:
        sib = index ^ 1
        if sib < len(layer): proof.append((layer[sib], "L" if sib < index else "R"))
        index //= 2
    return tuple(proof)

def verify(item, proof, expected_root):
    h = leaf_hash(item)
    for sib, side in proof:
        if side == "L": h = node_hash(sib, h)
        elif side == "R": h = node_hash(h, sib)
        else: return False
    return h == expected_root

def sides(size, index):
    """The L/R pattern of the proof for leaf `index` in a tree of `size`
    leaves. Distinct indices give distinct patterns, so checking a proof's
    sides against this pins which position it proves, not only membership."""
    out = []
    while size > 1:
        sib = index ^ 1
        if sib < size: out.append("L" if sib < index else "R")
        index //= 2; size = size // 2 + size % 2
    return out

def verify_at(item, proof, expected_root, size, index):
    if not 0 <= index < size: return False
    if [s for _, s in proof] != sides(size, index): return False
    return verify(item, proof, expected_root)
