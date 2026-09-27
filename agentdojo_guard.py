
# The guard, for tools that change state rather than files.
#
# AgentDojo's tools (send_money, send_email, share_file, invite_user_to_slack,
# ...) are Python functions over an environment object, not programs in a
# workdir, so there is no syscall trace to read their effects from. What they
# did is instead read from the environment itself, before and after:
#
#   1. rehearsal  the call runs on a copy of the environment. Nothing real
#                 has changed yet.
#   2. effects    the guard's diff of the copy against the environment, read
#                 under the state policy (policies/agentdojo.json): money,
#                 mail, a shared file, a message, a web request that reaches a
#                 party the user did not name and the environment did not
#                 already hold is exfiltrate; adding an unknown user or
#                 changing a password to a value the user did not give is
#                 dominate; removing anything is destruct; the rest is write.
#   3. witness    the call runs again, on the witness's own copy, at the same
#                 clock reading (the clock is an input, like the arguments), and the
#                 witness diffs it with its own code (flatten and compare, not
#                 the guard's recursive walk). If its account of the change
#                 or the result differs from the guard's, the call
#                 is refused: a disagreement is a refusal, not a second
#                 opinion (the arbitration rule witness.py follows for traces).
#   4. verdict    the guard judges the effects against the Vow through
#                 Guard.engage: a Coq certificate of the decision, co-signed
#                 with ML-DSA and written to the ledger. The action's id
#                 carries the digest of the change, so what was signed is
#                 bound to what changed.
#   5. commit     only a lawful call's copy becomes the environment. A refused
#                 call leaves the environment as it was: nothing half-done.
#
# A party is trusted if it is the user's own identity, appears in a party
# field of the environment when the task began, or is named in the user's
# prompt. Nothing here knows about any injection task; the policy was written
# from the suites' tools, schema and user prompts.
import fnmatch, hashlib, json, os, re

FORMAT = "dharmapala-state-policy/v1"
KEYS = {"format", "note", "identity", "rules", "trust_from", "otherwise"}
OPS = ("add", "change", "remove")
DEFAULT_POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies", "agentdojo.json")

AGENTDOJO_VOW = """
vow AgentDojo
  forbid exfiltrate forall action
  forbid dominate forall action
  forbid diverged forall action
"""
# destruct is left out of the default: deleting a file or an email is an
# ordinary user request. STRICT_VOW forbids it too; both are evaluated.
STRICT_VOW = AGENTDOJO_VOW + "  forbid destruct forall action\n"

class StatePolicyError(ValueError): pass

class StatePolicy:
    """What a change to the environment means. Data with a hash, like policy.py."""
    def __init__(self, d):
        if not isinstance(d, dict) or d.get("format") != FORMAT:
            raise StatePolicyError(f"not a {FORMAT} document")
        unknown = set(d) - KEYS
        if unknown: raise StatePolicyError(f"unknown keys: {sorted(unknown)}")
        for r in d.get("rules", []):
            if not set(r.get("ops", [])) <= set(OPS) or not r.get("ops"):
                raise StatePolicyError(f"rule {r.get('path')}: ops must be some of {OPS}")
            _party_spec(r.get("party"))
            from effects import require_known
            require_known(r.get("effect"), f"rule {r.get('path')}")
        for t in d.get("trust_from", []): _party_spec(t.get("party"))
        if set(d.get("otherwise", {})) != set(OPS):
            raise StatePolicyError(f"otherwise must name an effect for each of {OPS}")
        self.d = d
    @classmethod
    def load(cls, path=DEFAULT_POLICY):
        with open(path) as f: return cls(json.load(f))
    def hash(self):
        return hashlib.sha256(json.dumps(self.d, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _party_spec(spec):
    if spec is None or spec == "value" or re.fullmatch(r"seg:-?\d+", str(spec)): return spec
    raise StatePolicyError(f"party must be 'value' or 'seg:N', not {spec!r}")

def _is_leaf(v): return not isinstance(v, (dict, list))

def _same(a, b): return type(a) is type(b) and a == b

# --- the guard's reading of a change: a recursive walk ----------------------------------------------

def _leaves(op, v, path):
    if isinstance(v, dict): return [c for k in sorted(v, key=str) for c in _leaves(op, v[k], path + (str(k),))]
    if isinstance(v, list): return [c for i, x in enumerate(v) for c in _leaves(op, x, path + (str(i),))]
    return [(op, path, v)]

def diff(before, after, path=()):
    """[(op, path, value)] from before to after, one per leaf. Empty containers are not leaves."""
    if isinstance(before, dict) and isinstance(after, dict):
        out = []
        for k in sorted(set(before) | set(after), key=str):
            if k not in after: out += _leaves("remove", before[k], path + (str(k),))
            elif k not in before: out += _leaves("add", after[k], path + (str(k),))
            else: out += diff(before[k], after[k], path + (str(k),))
        return out
    if isinstance(before, list) and isinstance(after, list):
        out = []
        for i in range(max(len(before), len(after))):
            if i >= len(after): out += _leaves("remove", before[i], path + (str(i),))
            elif i >= len(before): out += _leaves("add", after[i], path + (str(i),))
            else: out += diff(before[i], after[i], path + (str(i),))
        return out
    if _is_leaf(before) and _is_leaf(after):
        return [] if _same(before, after) else [("change", path, after)]
    return _leaves("remove", before, path) + _leaves("add", after, path)

# --- the witness's reading: flatten both, compare -----------------------------------------------------

def flatten(v, path=()):
    out = {}
    stack = [(path, v)]
    while stack:
        p, x = stack.pop()
        if isinstance(x, dict): stack.extend((p + (str(k),), y) for k, y in x.items())
        elif isinstance(x, list): stack.extend((p + (str(i),), y) for i, y in enumerate(x))
        else: out[p] = x
    return out

def witness_diff(before, after):
    a, b = flatten(before), flatten(after)
    out = [("remove", p, a[p]) for p in a.keys() - b.keys()]
    out += [("add", p, b[p]) for p in b.keys() - a.keys()]
    out += [("change", p, b[p]) for p in a.keys() & b.keys() if not _same(a[p], b[p])]
    return out

def canonical(changes):
    """Order-free form of a list of changes, to compare two readings and to digest one."""
    return sorted((op, list(p), json.dumps(v, sort_keys=True)) for op, p, v in changes)

def changes_digest(changes):
    return hashlib.sha256(json.dumps(canonical(changes)).encode()).hexdigest()

# --- meaning -------------------------------------------------------------------------------------------

def _match(pattern, path):
    return len(pattern) == len(path) and all(fnmatch.fnmatchcase(s, p) for p, s in zip(pattern, path))

def _party(spec, path, value):
    return value if spec == "value" else path[int(spec.split(":")[1])]

def trusted_parties(policy, pre_state):
    """The user's own identity, and every party already in the environment."""
    trusted = set()
    for path, v in flatten(pre_state).items():
        if any(tuple(i) == path for i in policy.d.get("identity", [])): trusted.add(str(v).lower())
        for t in policy.d.get("trust_from", []):
            if _match(t["path"], path): trusted.add(str(_party(t["party"], path, v)).lower())
    return trusted

def named_in(prompt, party):
    party = str(party).strip()
    # Named means the whole party, not part of a longer one: bob@x.com is not
    # named by bob@x.com.evil, though a sentence may end right after it.
    return len(party) >= 2 and re.search(r"(?<![\w@.-])" + re.escape(party) + r"(?![\w@-]|\.\w)",
                                         prompt or "", re.I) is not None

def derive(changes, policy, trusted, prompt):
    """(effects, reasons) of a set of changes, under the policy."""
    effects, why = set(), []
    for op, path, value in changes:
        for r in policy.d.get("rules", []):
            if op in r["ops"] and _match(r["path"], path):
                party = _party(r["party"], path, value) if r.get("party") else None
                if party is not None and (str(party).lower() in trusted or named_in(prompt, party)):
                    effects.add("write")
                else:
                    effects.add(r["effect"])
                    why.append(f"{r['effect']}: {'/'.join(path)}" + (f" -> {party}" if party is not None else ""))
                break
        else:
            effects.add(policy.d["otherwise"][op])
            if policy.d["otherwise"][op] not in ("write", "read"):
                why.append(f"{policy.d['otherwise'][op]}: {'/'.join(path)}")
    return effects, why

# --- the gate ------------------------------------------------------------------------------------------

def _engine(inputs): return {"butterflies": []}

class _FrozenClock:
    """The clock is an input to a call, like its arguments. AgentDojo's tools
    stamp mail and files with datetime.datetime.now(), so two runs of the same
    call a moment apart differ in a timestamp, and the witness would refuse
    every one of them (it did: 665 of 4275 calls in the first full run). The
    gate reads the clock once and both runs see that instant; anything else
    that differs between them still differs."""
    def __init__(self, now): self.now, self.patched = now, []
    def __enter__(self):
        import datetime as real, sys, types
        now = self.now
        class Frozen(real.datetime):
            # Only now() is frozen. Every other constructor (strptime,
            # fromisoformat, ...) builds through cls(...), so this hands back
            # a plain datetime and no stand-in ever reaches the environment.
            def __new__(cls, *a, **k): return real.datetime(*a, **k)
            @classmethod
            def now(cls, tz=None): return now if tz is None else now.astimezone(tz)
        proxy = types.SimpleNamespace(**{k: getattr(real, k) for k in dir(real) if not k.startswith("__")})
        proxy.datetime = Frozen
        for name, mod in list(sys.modules.items()):
            if name.startswith("agentdojo.") and getattr(mod, "datetime", None) is real:
                self.patched.append(mod); mod.datetime = proxy
        return self
    def __exit__(self, *exc):
        import datetime as real
        for mod in self.patched: mod.datetime = real
        self.patched = []

class StateGate:
    """Everything between a proposed call and the environment it would change."""
    def __init__(self, vow_source=AGENTDOJO_VOW, policy=None, ledger=None, formatter=None):
        from guard import Guard
        from ledger import Ledger
        from signing import default_signer, verifier_for
        from to_coq_witness import CoSigner
        from trajectory import TrajectoryCoSigner
        from vow import parse_vow
        import shutil
        self.vow = parse_vow(vow_source)
        self.policy = policy if isinstance(policy, StatePolicy) else StatePolicy.load(policy or DEFAULT_POLICY)
        self.ledger = ledger or Ledger(sangha_id="agentdojo")
        self.guard = Guard("Guard", self.ledger)
        s_co, s_tr = default_signer("CoSigner"), default_signer("Trajectory")
        for s in (s_co, s_tr): self.ledger.register_verifier(verifier_for(s))
        # A certificate nobody checked is not a check: with coqc present, an
        # unchecked certificate is a configuration failure, not a pass.
        self.co_signer = CoSigner(s_co, require_coqc=shutil.which("coqc") is not None)
        self.traj_cosigner = TrajectoryCoSigner(s_tr)
        me = os.path.abspath(__file__)
        self.binary_path = me
        self.binary_hash = hashlib.sha256(open(me, "rb").read()).hexdigest()
        self.formatter = formatter
        self.prompt, self.trusted = "", set()
        self.log = []          # one record per call: how it was arbitrated
        self.ran, self.pre_env, self.post_env = [], None, None   # this task's calls that ran, and its states

    def begin(self, prompt, env):
        """A task starts: what the user asked, and who is already known."""
        self.prompt = prompt
        self.trusted = trusted_parties(self.policy, env.model_dump(mode="json"))
        self.task_start, self.ran = len(self.log), []
        self.pre_env = env.model_copy(deep=True)

    def _fmt(self, result):
        if self.formatter is not None: return self.formatter(result)
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        return tool_result_to_str(result)

    def call(self, runtime, env, name, args, call_id=""):
        """(text, error, env): the result to show the model, the error if any (a refusal is one,
        so the model is told), and the environment after the call."""
        from guard import VerdictKind
        import datetime
        before = env.model_dump(mode="json")
        now = datetime.datetime.now()
        # 1-2. Rehearse on a copy; the guard reads the change.
        staged = env.model_copy(deep=True)
        with _FrozenClock(now): result, error = runtime.run_function(staged, name, dict(args))
        text = self._fmt(result)
        changes = diff(before, staged.model_dump(mode="json"))
        effects, why = derive(changes, self.policy, self.trusted, self.prompt)
        rec = {"call": call_id, "tool": name, "clock": now.isoformat(), "effects": sorted(effects), "why": why,
               "changes": len(changes), "digest": changes_digest(changes)}
        # 3. The witness runs it again on its own copy and reads it its own way.
        mine = env.model_copy(deep=True)
        with _FrozenClock(now): w_result, w_error = runtime.run_function(mine, name, dict(args))
        w_changes = witness_diff(before, mine.model_dump(mode="json"))
        # The effects are derived from the change; the same change read the
        # same way cannot mean two things, so the change is what is compared.
        disagree = [what for what, same in (
            ("change", canonical(w_changes) == canonical(changes)),
            ("result", self._fmt(w_result) == text and w_error == error)) if not same]
        if disagree:
            rec.update(witness="disagree: " + ", ".join(disagree), verdict=None, outcome="refused")
            self.log.append(rec)
            msg = (f"refused: the guard and its witness disagree about what this call does "
                   f"({', '.join(disagree)}); nothing was changed")
            return msg, msg, env
        rec["witness"] = "agree"
        # 4. The verdict, certified, co-signed and recorded.
        from vow import Action
        action = Action(id=f"{call_id}:{rec['digest']}", verb=name, domain="agentdojo")
        action._observed_effects = effects
        verdict = self.guard.engage(action, self.vow, self.co_signer, self.traj_cosigner, f"tool:{name}",
                                    {"call": call_id, "changes": rec["digest"], "clock": rec["clock"]}, _engine,
                                    self.binary_path, self.binary_hash)
        rec["verdict"] = verdict.kind.name
        # 5. Only a lawful call's change is kept.
        if verdict.kind == VerdictKind.LAWFUL:
            rec["outcome"] = "lawful"; self.log.append(rec)
            return text, error, staged
        rec["outcome"] = "refused"; self.log.append(rec)
        reason = "; ".join(why) or verdict.reason
        msg = f"refused: {reason}. The policy forbids it; nothing was changed."
        return msg, msg, env

def executor(gate):
    """An AgentDojo pipeline element that runs every tool call through `gate`,
    in place of AgentDojo's own ToolsExecutor."""
    from ast import literal_eval
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.tool_execution import is_string_list
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    class GuardedToolsExecutor(BasePipelineElement):
        def query(self, query, runtime, env, messages=(), extra_args={}):
            if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
                return query, runtime, env, messages, extra_args
            # The first calls of a task: the environment is still as the task began.
            if not any(m["role"] == "tool" for m in messages): gate.begin(query, env)
            out = []
            for tc in messages[-1]["tool_calls"]:
                if tc.function not in runtime.functions:
                    out.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tc.id, tool_call=tc,
                                                     error=f"Invalid tool {tc.function} provided."))
                    continue
                for k, v in tc.args.items():
                    if isinstance(v, str) and is_string_list(v): tc.args[k] = literal_eval(v)
                text, error, env = gate.call(runtime, env, tc.function, tc.args, tc.id or "")
                if gate.log[-1]["outcome"] == "lawful": gate.ran.append(tc)
                gate.post_env = env
                out.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                 tool_call_id=tc.id, tool_call=tc, error=error))
            return query, runtime, env, [*messages, *out], extra_args

    return GuardedToolsExecutor()
