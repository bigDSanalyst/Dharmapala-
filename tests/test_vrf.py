import hashlib

import pytest

import tests.support  # noqa: F401
from vrf import Counterparty, GuardNonce, selection_seed

def test_the_order_is_enforced():
    gn = GuardNonce(0)
    with pytest.raises(RuntimeError): gn.receive(b"x" * 32)      # before commit
    gn.commit()
    with pytest.raises(RuntimeError): gn.commit()
    with pytest.raises(RuntimeError): gn.reveal()                # before contribution
    with pytest.raises(RuntimeError): gn.seed()
    gn.receive(b"x" * 32)
    with pytest.raises(RuntimeError): gn.receive(b"y" * 32)
    assert len(gn.seed()) == 32

def test_the_seed_depends_on_the_late_contribution():
    nonce = b"n" * 32; c = hashlib.sha256(nonce).hexdigest()
    assert selection_seed(0, c, b"a" * 32, nonce) != selection_seed(0, c, b"b" * 32, nonce)

def test_a_nonce_that_does_not_open_the_commitment_is_rejected():
    c = hashlib.sha256(b"n" * 32).hexdigest()
    with pytest.raises(ValueError): selection_seed(0, c, b"a" * 32, b"m" * 32)

def test_the_counterparty_contributes_once_per_epoch():
    cp = Counterparty(); cp.contribute(0, "ab")
    with pytest.raises(RuntimeError): cp.contribute(0, "cd")
    with pytest.raises(ValueError): cp.contribute(1, "")
