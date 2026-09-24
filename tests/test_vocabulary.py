import re

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
from effects import EFFECTS, UnknownEffect
from observation import observe
from vow import Clause, Op, Vow, parse_vow
from vow_lean import emit_vow_compliance

def test_lean_declares_the_same_effects():
    src = (ROOT / "lean" / "Dharma" / "Effects.lean").read_text()
    body = src.split("inductive Effect where", 1)[1].split("deriving", 1)[0]
    assert tuple(re.findall(r"\|\s*(\w+)", body)) == EFFECTS

def test_observation_emits_only_known_effects():
    calls = [("file_read", {"path": "/etc/shadow"}, {}), ("http_get", {"url": "https://pastebin.com"}, {}),
             ("shell", {"cmd": "curl x; rm -rf /; pkill y"}, {})] + \
            [("file_write", {"path": f"f{i}"}, {}) for i in range(3)]
    seen = observe(calls, "/tmp")
    assert seen and seen <= set(EFFECTS)

@pytest.mark.parametrize("line", [
    "forbid exfiltrat forall action",
    "commit reed forall action",
    "trajectory t: never effect:exfiltrat after effect:read",
])
def test_a_misspelled_effect_is_rejected(line):
    with pytest.raises(SyntaxError, match="unknown effect"):
        parse_vow(f"vow T\n  {line}\n")

def test_the_emitter_refuses_an_unknown_effect():
    v = Vow("T", [Clause(Op.FORBID, "exfiltrat", "action")])
    with pytest.raises(UnknownEffect):
        emit_vow_compliance({"exfiltrate"}, v)
