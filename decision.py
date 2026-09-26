
# The guard's decision as a Coq theorem. A record used to carry a certificate
# about the engine's butterfly arithmetic and nothing about the verdict; this
# makes the verdict itself machine-checked: coqc accepts `violations = [..]`
# only if that list really is the forbidden effects the action carries.
from dataclasses import dataclass
from effects import EFFECTS, require_known

def _ctor(e): return f"E_{require_known(e, 'decision')}"

def forbidden_of(vow):
    out = []
    for c in vow.action_clauses():
        if c.op.name == "FORBID" and c.arg1 not in out: out.append(c.arg1)
    return tuple(out)

def violations(effects, forbidden):
    return [f for f in forbidden if f in effects]

def verdict_of(effects, forbidden):
    return "LEARNING" if violations(effects, forbidden) else "LAWFUL"

@dataclass(frozen=True)
class Decision:
    effects: tuple; forbidden: tuple; verdict: str
    action_digest: str; vow_hash: str
    evidence_digest: str = ""       # what the effects were read from, when there is a record of it
    @classmethod
    def of(cls, action, vow):
        effects = tuple(sorted(action.effects()))
        forbidden = forbidden_of(vow)
        ev = getattr(action, "_evidence", None)
        if ev is not None:
            from critic_loop import evidence_digest
            ev = evidence_digest(ev)
        return cls(effects, forbidden, verdict_of(effects, forbidden),
                   action.canonical_digest(), vow.hash(), ev or "")
    def coq_preamble(self):
        return ["Require Import List. Import ListNotations.",
                "Inductive Effect := " + " | ".join(_ctor(e) for e in EFFECTS) + ".",
                "Scheme Equality for Effect.",
                "Definition observed : list Effect := [" + "; ".join(_ctor(e) for e in self.effects) + "].",
                "Definition forbidden : list Effect := [" + "; ".join(_ctor(e) for e in self.forbidden) + "].",
                "Definition violations : list Effect :=",
                "  filter (fun f => existsb (Effect_beq f) observed) forbidden."]
    def coq_statement(self):
        return "violations = [" + "; ".join(_ctor(e) for e in violations(self.effects, self.forbidden)) + "]"
