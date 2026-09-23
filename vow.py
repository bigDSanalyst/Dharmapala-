
import hashlib, re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

class Op(Enum):
    COMMIT = auto(); FORBID = auto(); BALANCE = auto(); FIELD = auto()

@dataclass(frozen=True)
class Clause:
    op: Op; arg1: str; arg2: str; engine: Optional[str] = None

@dataclass
class Vow:
    name: str
    clauses: list = field(default_factory=list)
    engine_map: dict = field(default_factory=dict)
    def obligations(self, action):
        out = []
        effects = action.effects()
        for c in self.clauses:
            if not hasattr(c, 'op'): continue
            if c.op == Op.FORBID and c.arg1 in effects:
                out.append((c, "vow/forbid"))
            elif c.op == Op.COMMIT and c.arg1 in effects:
                out.append((c, self.engine_map.get(c.arg2, "gf2")))
        return out
    def trajectories(self):
        from trajectory import TrajectoryClause
        return [c for c in self.clauses if isinstance(c, TrajectoryClause)]
    def action_clauses(self):
        from trajectory import TrajectoryClause
        return [c for c in self.clauses if not isinstance(c, TrajectoryClause)]
    def hash(self):
        canonical = []
        for c in self.clauses:
            if hasattr(c, 'op'):
                canonical.append(f"{c.op.name}:{c.arg1}:{c.arg2}:{c.engine or ''}")
            else:
                canonical.append(f"TRAJ:{c.name}:{c.pattern.value}:{c.subject}:{c.anchor}")
        canonical = sorted(canonical)
        eng = sorted(f"{k}={v}" for k, v in self.engine_map.items())
        return hashlib.sha256(("|".join(canonical) + "||" + "|".join(eng)).encode()).hexdigest()

_CLAUSE_RE = re.compile(
    r"^\s*(commit|forbid|balance|field)\s+"
    r"(?:(\w+)\s+forall\s+(\w+)|(\w+)\s+against\s+(\w+)|(\w+)\s+is\s+(\w+))\s*$")
_TRAJ_RE = re.compile(
    r"^\s*trajectory\s+(\w+)\s*:\s*"
    r"(?:never\s+(\S+)\s+after\s+(\S+)"
    r"|before\s+(\S+)\s+require\s+(\S+)"
    r"|after\s+(\S+)\s+eventually\s+(\S+))\s*$")

def parse_vow(source):
    from trajectory import TrajectoryClause, Pattern
    vow = None
    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("vow "):
            vow = Vow(name=line[4:].strip()); continue
        if vow is None:
            raise SyntaxError(f"line {lineno}: clause before 'vow <name>'")
        m = _TRAJ_RE.match(line)
        if m:
            name = m.group(1)
            if m.group(2):
                vow.clauses.append(TrajectoryClause(name, Pattern.NEVER_AFTER, m.group(2), m.group(3)))
            elif m.group(4):
                vow.clauses.append(TrajectoryClause(name, Pattern.REQUIRE_BEFORE, m.group(4), m.group(5)))
            else:
                vow.clauses.append(TrajectoryClause(name, Pattern.EVENTUALLY_AFTER, m.group(7), m.group(6)))
            continue
        m = _CLAUSE_RE.match(line)
        if not m: raise SyntaxError(f"line {lineno}: {line!r}")
        op = Op[m.group(1).upper()]
        if op in (Op.COMMIT, Op.FORBID):
            vow.clauses.append(Clause(op, m.group(2), m.group(3)))
        elif op == Op.BALANCE:
            vow.clauses.append(Clause(op, m.group(4), m.group(5)))
        elif op == Op.FIELD:
            domain, engine = m.group(6), m.group(7)
            vow.engine_map[domain] = engine
            vow.clauses.append(Clause(op, domain, engine, engine=engine))
    if vow is None: raise SyntaxError("empty Vow")
    return vow

@dataclass
class Action:
    id: str; verb: str; domain: str; payload: dict = field(default_factory=dict)
    def effects(self):
        if hasattr(self, "_observed_effects"):
            return set(self._observed_effects)
        return set(self.payload.get("effects", []))
    def matches(self, predicate):
        if predicate is None: return False
        if predicate.startswith("effect:"): return predicate[7:] in self.effects()
        if predicate.startswith("verb:"): return predicate[5:] == self.verb
        return predicate in self.effects() or predicate == self.verb
    def canonical_digest(self):
        payload = f"{self.id}|{self.verb}|{self.domain}|" + ",".join(sorted(self.effects()))
        return hashlib.sha256(payload.encode()).hexdigest()
