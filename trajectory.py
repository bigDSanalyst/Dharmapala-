
import hashlib, json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional

class Pattern(Enum):
    NEVER_AFTER = "never_after"; REQUIRE_BEFORE = "require_before"
    EVENTUALLY_AFTER = "eventually_after"

@dataclass(frozen=True)
class TrajectoryClause:
    name: str; pattern: Pattern; subject: str; anchor: Optional[str] = None

class Automaton:
    def __init__(self, initial, rejecting, accepting, transitions):
        self.initial = initial; self.rejecting = frozenset(rejecting)
        self.accepting = frozenset(accepting); self.transitions = transitions
    def step(self, state, action):
        if state in self.rejecting: return state
        for (s, pred), target in self.transitions.items():
            if s == state and action.matches(pred): return target
        return state
    def rejects(self, state): return state in self.rejecting
    def accepts_end(self, state): return state in self.accepting

def compile_clause(c):
    if c.pattern == Pattern.NEVER_AFTER:
        return Automaton(0, {2}, {0, 1}, {(0, c.anchor): 1, (1, c.subject): 2})
    if c.pattern == Pattern.REQUIRE_BEFORE:
        return Automaton(0, {2}, {0, 1},
                         {(0, c.anchor): 1, (0, c.subject): 2, (1, c.subject): 1})
    if c.pattern == Pattern.EVENTUALLY_AFTER:
        return Automaton(0, set(), {0},
                         {(0, c.anchor): 1, (0, c.subject): 0,
                          (1, c.subject): 0, (1, c.anchor): 1})
    raise ValueError(f"unknown pattern: {c.pattern}")

class TrajectoryChecker:
    def __init__(self, clauses):
        self.clauses = list(clauses)
        self.automata = [compile_clause(c) for c in self.clauses]
    def initial(self): return tuple(a.initial for a in self.automata)
    def step(self, state, action):
        return tuple(self.automata[i].step(state[i], action)
                     for i in range(len(self.automata)))
    def evaluate_state(self, prior_state, next_action):
        if len(prior_state) != len(self.automata):
            prior_state = self.initial()
        new_state = self.step(prior_state, next_action)
        violations = []
        for i, c in enumerate(self.clauses):
            if self.automata[i].rejects(new_state[i]): violations.append(c.name)
        for i, c in enumerate(self.clauses):
            if not self.automata[i].accepts_end(new_state[i]):
                violations.append(c.name + ":pending")
        return new_state, violations

@dataclass(frozen=True)
class TrajectoryAttestation:
    signer_id: str; prior_state: tuple; action_digest: str; verdict: str
    signature: str = ""
    def payload(self):
        return json.dumps({"prior_state": list(self.prior_state),
                           "action": self.action_digest,
                           "verdict": self.verdict,
                           "signer": self.signer_id}, sort_keys=True).encode()
    def attestation_hash(self):
        return hashlib.sha256(self.payload()).hexdigest()

class TrajectoryCoSigner:
    def __init__(self, signer):
        self.id = signer.id; self._signer = signer
    def cosign(self, clauses, prior_state, action, guard_verdict):
        checker = TrajectoryChecker(clauses)
        if len(prior_state) != len(checker.automata): prior_state = checker.initial()
        _, violations = checker.evaluate_state(prior_state, action)
        immediate = [v for v in violations if not v.endswith(":pending")]
        my_verdict = "LEARNING" if immediate else "LAWFUL"
        if my_verdict != guard_verdict:
            return False, f"verdict mismatch: guard={guard_verdict} cosigner={my_verdict}"
        a = TrajectoryAttestation(self.id, tuple(prior_state),
                                  action.canonical_digest(), guard_verdict)
        return True, replace(a, signature=self._signer.sign(a.payload()).hex())
