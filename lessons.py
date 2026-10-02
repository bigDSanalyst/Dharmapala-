"""Lessons: refusals learned from attacks that got past the guard.

The state guard (agentdojo_guard.py) judges what a call does to parties. It
cannot see where a call's arguments came from: a link the attacker wrote,
sent to a colleague the user already knows, changes the environment exactly
as a link the user asked for would. Self-Evolving Defense (SED, 2026) learns
from such failures: a judge marks a trajectory harmful, and the failure is
distilled into a policy that is used on later episodes.

This is that loop, under three constraints SED does not have:

  tighten-only  A lesson can only refuse a call the guard would have allowed.
                It is consulted after the guard's verdict, and only when that
                verdict is lawful; it has no way to say "allow". A wrong
                lesson costs utility, never safety.
  admitted      A candidate lesson is kept only if it refuses none of the
                calls of the known-good trajectories it is checked against
                (SED's utility constraint, made a gate: unconditional refusal
                stops every attack and every task).
  append-only   Each lesson carries the hash of the book before it, and the
                book carries the hash of all of it. Editing, removing or
                reordering a lesson breaks the chain, and a book with a broken
                chain does not load. A chain kept in the same file can be
                rewritten end to end by whoever can write the file; what
                binds a run to a book is its hash, which every refusal and
                every result records, and which load(expect=...) checks.

A lesson is deterministic and names what it checks: a tool, an argument, a
kind of token in it (a URL, an email address, an IBAN, or the whole value),
and optionally the token itself. It fires when that argument carries a token
of that kind which the user's prompt does not name. Which trajectories are
harmful is the judge's call (AgentDojo's own security check in
eval_lessons.py; it could be a model); what a lesson is, and whether it is
admitted, is not.
"""
import hashlib, json, re

from agentdojo_guard import named_in

FORMAT = "dharmapala-lessons/v1"
KINDS = ("url", "email", "iban", "value")
LESSON_KEYS = {"id", "tool", "arg", "kind", "value", "learned_from", "judge", "prev"}
VALUE_MAX = 80          # a longer argument is text, not a name; only its tokens are read

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_TLD = r"(?:com|org|net|io|co|info|biz|edu|gov|ai|dev|app|me|uk|de|fr|es|it|nl|ch|eu|us|ru|cn)"
_URL = re.compile(r"(?:https?://[^\s\"'<>)]+|(?:www\.)?(?:[a-z0-9-]+\.)+" + _TLD + r"(?![a-z0-9-])(?:/[^\s\"'<>)]*)?)",
                  re.I)
_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9*]{8,30}(?![A-Z0-9*])")

class LessonError(ValueError): pass

def _digest(lessons):
    return hashlib.sha256(json.dumps(lessons, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def tokens(text, kind):
    """The tokens of one kind in a string argument."""
    if kind == "email": return _EMAIL.findall(text)
    if kind == "url": return [u.rstrip(".,;:") for u in _URL.findall(_EMAIL.sub(" ", text))]
    if kind == "iban": return _IBAN.findall(text)
    if kind == "value": return [text.strip()] if 2 <= len(text.strip()) <= VALUE_MAX and "\n" not in text else []
    raise LessonError(f"unknown kind {kind!r}")

def _strings(v):
    if isinstance(v, str): return [v]
    if isinstance(v, (list, tuple)): return [x for x in v if isinstance(x, str)]
    return []

def unnamed(args, prompt, only_arg=None):
    """[(arg, kind, token)]: every token in the call's arguments that the user's prompt does not name."""
    out = []
    for arg in sorted(args):
        if only_arg is not None and arg != only_arg: continue
        for s in _strings(args[arg]):
            for kind in KINDS:
                out += [(arg, kind, t) for t in tokens(s, kind) if not named_in(prompt, t)]
    return out

def matches(lesson, tool, args, prompt):
    """The token the lesson refuses this call for, or None."""
    if lesson["tool"] != tool or lesson["arg"] not in args: return None
    for _, kind, t in unnamed(args, prompt, lesson["arg"]):
        if kind == lesson["kind"] and (lesson["value"] is None or t.lower() == lesson["value"].lower()):
            return t
    return None

class Lessons:
    """A book of lessons: data with a hash, like the state policy."""
    def __init__(self, d):
        if not isinstance(d, dict) or d.get("format") != FORMAT or set(d) != {"format", "head", "lessons"}:
            raise LessonError(f"not a {FORMAT} document")
        for i, l in enumerate(d["lessons"]):
            if not isinstance(l, dict) or set(l) != LESSON_KEYS:
                raise LessonError(f"lesson {i}: keys must be exactly {sorted(LESSON_KEYS)}")
            if l["kind"] not in KINDS: raise LessonError(f"lesson {i}: unknown kind {l['kind']!r}")
            if not (isinstance(l["tool"], str) and isinstance(l["arg"], str) and l["tool"] and l["arg"]):
                raise LessonError(f"lesson {i}: tool and arg must be named")
            if l["value"] is not None and not isinstance(l["value"], str):
                raise LessonError(f"lesson {i}: value must be a string or null")
            if l["id"] != f"L{i + 1}": raise LessonError(f"lesson {i}: id must be L{i + 1}, not {l['id']!r}")
            if l["prev"] != _digest(d["lessons"][:i]):
                raise LessonError(f"lesson {l['id']}: the book before it is not the one it was learned on")
        if d["head"] != _digest(d["lessons"]):
            raise LessonError("the book's head is not the hash of its lessons: a lesson was changed")
        self.d = d

    @classmethod
    def empty(cls): return cls({"format": FORMAT, "head": _digest([]), "lessons": []})
    @classmethod
    def load(cls, path, expect=None):
        with open(path) as f: book = cls(json.load(f))
        if expect is not None and book.hash() != expect:
            raise LessonError(f"{path}: book {book.hash()[:16]} is not the expected {expect[:16]}")
        return book
    def save(self, path):
        with open(path, "w") as f: json.dump(self.d, f, indent=1, sort_keys=True); f.write("\n")
    def hash(self): return _digest(self.d["lessons"])
    def __len__(self): return len(self.d["lessons"])
    def __iter__(self): return iter(self.d["lessons"])

    def check(self, tool, args, prompt):
        """(lesson, token) for the first lesson that refuses this call, or None."""
        for l in self.d["lessons"]:
            t = matches(l, tool, args, prompt)
            if t is not None: return l, t
        return None

    def add(self, tool, arg, kind, value, learned_from, judge):
        """A new book: this one with a lesson appended. This one is unchanged."""
        n = self.d["lessons"]
        lesson = {"id": f"L{len(n) + 1}", "tool": tool, "arg": arg, "kind": kind, "value": value,
                  "learned_from": learned_from, "judge": judge, "prev": _digest(n)}
        return Lessons({"format": FORMAT, "head": _digest([*n, lesson]), "lessons": [*n, lesson]})

# --- learning ------------------------------------------------------------------------------------------

def candidates(call, prompt):
    """Lessons that would refuse this call, the most general first: a kind of token in an argument
    before one token, and a URL, an address or an IBAN before a whole value."""
    found = unnamed(call["args"], prompt)
    rank = {k: i for i, k in enumerate(KINDS)}
    found.sort(key=lambda x: rank[x[1]])
    out, seen = [], set()
    for general in (True, False):
        for arg, kind, t in found:
            c = (call["tool"], arg, kind, None if general else t)
            if c not in seen: seen.add(c); out.append(c)
    return out

def refuses(candidate, benign):
    """The known-good calls a candidate lesson would refuse."""
    tool, arg, kind, value = candidate
    probe = {"tool": tool, "arg": arg, "kind": kind, "value": value}
    return [(b["id"], c["tool"]) for b in benign for c in b["calls"] if matches(probe, c["tool"], c["args"], b["prompt"])]

def learn(book, harmful, benign, judge):
    """Learn from trajectories a judge called harmful, checked against trajectories known to be good.

    harmful: [{"id", "prompt", "calls": the calls the judge holds responsible}]
    benign:  [{"id", "prompt", "calls": every call the task made}]
    Returns (the new book, a report of what was admitted, rejected and already covered)."""
    report = []
    for h in harmful:
        for call in h["calls"]:
            if book.check(call["tool"], call["args"], h["prompt"]):
                report.append({"from": h["id"], "tool": call["tool"], "outcome": "covered"}); continue
            for cand in candidates(call, h["prompt"]):
                blocked = refuses(cand, benign)
                if blocked:
                    report.append({"from": h["id"], "candidate": list(cand), "outcome": "rejected",
                                   "would_refuse": sorted({f"{i}:{t}" for i, t in blocked})})
                    continue
                book = book.add(*cand, learned_from=h["id"], judge=judge)
                report.append({"from": h["id"], "candidate": list(cand), "outcome": "admitted",
                               "lesson": book.d["lessons"][-1]["id"]})
                break
            else:
                report.append({"from": h["id"], "tool": call["tool"], "outcome": "nothing admissible"})
    return book, report
