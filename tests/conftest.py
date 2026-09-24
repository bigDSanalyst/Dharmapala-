import shutil, sys

import pytest

from tests.support import lake_critic

@pytest.fixture
def without(monkeypatch):
    """Make one toolchain unavailable for the rest of the test."""
    real_which = shutil.which
    def remove(name):
        if name == "lean":
            monkeypatch.setattr(lake_critic, "_LEAN", None)
            monkeypatch.setattr(lake_critic, "_LEAN_STATUS", "removed by test")
        elif name == "coqc":
            monkeypatch.setattr(shutil, "which",
                                lambda n, *a, **k: None if n == "coqc" else real_which(n, *a, **k))
        elif name == "dilithium-py":
            monkeypatch.setitem(sys.modules, "dilithium_py", None)
            monkeypatch.setitem(sys.modules, "dilithium_py.ml_dsa", None)
        else:
            raise ValueError(name)
    return remove
