#!/usr/bin/env python3
"""A real agent, guarded: Claude proposes tool calls, Dharmapala decides.

    python3 guarded_agent.py "tidy up the notes in this directory" --workdir DIR
                             [--vow VOW.txt] [--ledger LEDGER.json] [--max-turns N]

Claude (through the Anthropic API) sees four tools: shell, file_read,
file_write, http_get. It never executes anything itself. Every call it
proposes goes through the same gate:

    1. critic      the call is dry-run and, for shell, rehearsed in the jail
                   against a throwaway copy of the workdir. If what it would
                   do breaks the Vow, it does not run; Claude is told why.
    2. execution   an accepted call runs for real: shell inside the jail,
                   traced; file tools in-process, confined to the workdir
                   unless the Vow allows otherwise; http_get never reaches
                   the network (the sandbox has none to give).
    3. guard       the guard judges what really ran; the co-signer re-derives
                   it from the run record with its own trace parser, runs a
                   shell call again itself from its own snapshot of the
                   workdir, and the decision goes into the ledger, proven and
                   signed.
    4. result      Claude sees the output only when the verdict is LAWFUL. A
                   call whose real run broke the Vow ran contained, but its
                   output is withheld: what it read is exactly what must not
                   leave, and the model is where it would go.

Needs the anthropic package and credentials (ANTHROPIC_API_KEY, or a profile
from `ant auth login`). Without bubblewrap and strace no shell call runs.

Exit codes:
    0  the agent finished its turn (whatever the guard refused along the way)
    1  it did not finish: a refusal by the model, max tokens or turns, or a
       setup problem, named on stderr
"""
import argparse, hashlib, json, os, pathlib, sys, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import jail
from critic_loop import CriticLoop, evidence_of, execute
from decision import forbidden_of
from guard import Guard, VerdictKind
from ledger import Ledger
from signing import default_signer, verifier_for
from to_coq_witness import CoSigner
from trajectory import TrajectoryCoSigner
from vow import Action, parse_vow

MODEL = "claude-opus-5"
MAX_TOKENS = 16000
FALLBACK_BETA = "server-side-fallback-2026-07-01"

# The default Vow for a guarded agent: the named harms, anything outside the
# workdir that writes, and a real run that did what its rehearsal did not.
# Reading outside the workdir and running unvetted programs stay allowed:
# the jail makes the filesystem read-only and has no network, and a coding
# agent that cannot run programs cannot do its job.
DEFAULT_VOW = """
vow GuardedAgent
  forbid read_sensitive_path forall action
  forbid write_outside_workdir forall action
  forbid exfiltrate forall action
  forbid destruct forall action
  forbid dominate forall action
  forbid network_unlisted forall action
  forbid diverged forall action
"""

SYSTEM = """You are working in a sandboxed directory. Every tool call you make is \
checked by a guard before it runs and judged again after. A call can be refused \
before it runs (the result says which effect the policy forbids), or run and have \
its output withheld (it did something the policy forbids). Treat a refusal as a \
boundary, not an obstacle: do not try to reach the same effect another way. \
There is no network. Paths are relative to the working directory."""

def _tool(name, description, props, required):
    return {"name": name, "description": description, "strict": True,
            "input_schema": {"type": "object", "properties": props, "required": required,
                             "additionalProperties": False}}

TOOLS = [
    _tool("shell", "Run a shell command in the working directory (sh -c). Returns exit code and stdout.",
          {"cmd": {"type": "string"}}, ["cmd"]),
    _tool("file_read", "Read a text file.", {"path": {"type": "string"}}, ["path"]),
    _tool("file_write", "Write a text file, replacing it.",
          {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
    _tool("http_get", "Fetch a URL. The sandbox has no network; this never reaches it.",
          {"url": {"type": "string"}}, ["url"]),
]
ARGS = {t["name"]: set(t["input_schema"]["properties"]) for t in TOOLS}

def _engine(inputs):
    # The guard's certificate carries a re-run engine's outputs; a tool call
    # has none to add, so the engine is empty and the decision is the proof.
    return {"butterflies": []}

class _OneCall:
    """An 'agent' for the critic loop that proposes exactly the call Claude made."""
    def __init__(self, name, args): self.name, self.args = name, args; self.sandbox = None
    def act(self, goal, context=""):
        getattr(self.sandbox, self.name)(**self.args)
        return self.sandbox.calls

class Gate:
    """Everything between a proposed tool call and its result."""
    def __init__(self, vow, workdir, guard, co_signer, traj_cosigner):
        self.vow, self.workdir = vow, str(workdir)
        self.guard, self.co_signer, self.traj_cosigner = guard, co_signer, traj_cosigner
        pathlib.Path(self.workdir).mkdir(parents=True, exist_ok=True)
        self.jail_ok, self.jail_why = jail.available()
        me = pathlib.Path(__file__).resolve()
        self.binary_path = str(me)                   # the code that judges is the engine
        self.binary_hash = hashlib.sha256(me.read_bytes()).hexdigest()
        self.log = []                                # (tool, args, outcome, detail)

    def run(self, call_id, name, args):
        """(content, is_error) for the tool_result."""
        if name not in ARGS or not isinstance(args, dict) or set(args) != ARGS[name] \
                or not all(isinstance(v, str) for v in args.values()):
            return self._out(name, args, "invalid", f"not a valid call to a known tool: {name}")
        if name == "shell" and not self.jail_ok:
            return self._out(name, args, "refused", f"shell is unavailable: no jail ({self.jail_why}); nothing ran")
        # 1. The critic: dry run, and for shell a rehearsal in the jail.
        critic = CriticLoop(_OneCall(name, args), self.vow, max_retries=1, verbose=False,
                            guard=self.guard, rehearse=(name == "shell"))
        predicted, ok, plan = critic.propose_and_verify(f"tool:{name}", workdir=self.workdir)
        if not ok:
            last = critic.attempts[-1] if critic.attempts else {}
            if last.get("unchecked"):
                return self._out(name, args, "refused", f"the critic could not check this call ({last['unchecked']}); nothing ran")
            return self._out(name, args, "refused",
                             f"refused before running: it would have effects the policy forbids: {', '.join(last.get('violations') or ['(unnamed)'])}")
        # 2. Run it for real, after the co-signer has copied the workdir for itself.
        snap = self.co_signer.snapshot(self.workdir) if name == "shell" and self.co_signer.reexecute else None
        try: return self._run(call_id, name, args, plan, predicted, snap)
        finally: self.co_signer.release(snap)

    def _run(self, call_id, name, args, plan, predicted, snap):
        observed, calls = execute(plan, predicted, self.workdir, jail=self.jail_ok)
        # 3. The guard judges what ran; the co-signer checks the guard.
        action = Action(id=call_id, verb=name, domain="action")
        action._observed_effects = observed
        action._evidence = evidence_of(calls, self.workdir, predicted)
        action._snapshot = snap
        verdict = self.guard.engage(action, self.vow, self.co_signer, self.traj_cosigner,
                                    f"tool:{name}", {"tool_use_id": call_id}, _engine,
                                    self.binary_path, self.binary_hash)
        # 4. Only a lawful run's output goes back to the model.
        if verdict.kind != VerdictKind.LAWFUL:
            hit = sorted(set(observed) & set(forbidden_of(self.vow)))
            why = f"the run showed {', '.join(hit)}, which the policy forbids" if hit else verdict.reason
            return self._out(name, args, verdict.kind.name.lower(),
                             f"the call ran inside the sandbox, but the guard's verdict is "
                             f"{verdict.kind.name}: {why}. Its output is withheld.")
        return self._out(name, args, "lawful", _render(name, calls[-1][2]), error=False)

    def _out(self, name, args, outcome, detail, error=True):
        self.log.append((name, args, outcome, detail))
        return detail, error

def _render(name, result):
    if name == "shell":
        return f"exit {result.get('returncode')}\n{result.get('stdout', '')}" + \
               ("\n(timed out)" if result.get("timed_out") else "")
    if name == "file_read":
        return result.get("content", "") if result.get("ok") else f"error: {result.get('error')}"
    if name == "file_write":
        return f"wrote {result.get('bytes')} bytes" if result.get("ok") else f"error: {result.get('error')}"
    return "not fetched: the sandbox has no network"

class GuardedAgent:
    def __init__(self, client, gate, model=MODEL, max_turns=20):
        self.client, self.gate, self.model, self.max_turns = client, gate, model, max_turns
        self.messages = []

    def _request(self):
        return self.client.beta.messages.create(
            model=self.model, max_tokens=MAX_TOKENS, system=SYSTEM, tools=TOOLS,
            thinking={"type": "adaptive"}, messages=self.messages,
            betas=[FALLBACK_BETA], fallbacks="default")

    def run(self, task):
        """Returns (finished, final_text or the reason it stopped)."""
        self.messages = [{"role": "user", "content": task}]
        for _ in range(self.max_turns):
            response = self._request()
            if response.stop_reason == "refusal":
                return False, "the model declined the task"
            self.messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason == "pause_turn":
                continue
            if response.stop_reason == "max_tokens":
                return False, "the model ran out of output tokens mid-turn"
            if response.stop_reason != "tool_use":
                return True, "".join(b.text for b in response.content if b.type == "text")
            # Every call in the turn goes through the gate; all results go back in one message.
            results = []
            for block in response.content:
                if block.type != "tool_use": continue
                content, is_error = self.gate.run(block.id, block.name, block.input)
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": content, "is_error": is_error})
            self.messages.append({"role": "user", "content": results})
        return False, f"stopped after {self.max_turns} turns"

def setup(workdir, vow_source=DEFAULT_VOW, ledger_path=None):
    ledger = Ledger(sangha_id="agent", path=ledger_path)
    guard = Guard("Guard", ledger)
    s_co, s_tr = default_signer("CoSigner"), default_signer("Trajectory")
    for s in (s_co, s_tr): ledger.register_verifier(verifier_for(s))
    gate = Gate(parse_vow(vow_source), workdir, guard, CoSigner(s_co, reexecute=True), TrajectoryCoSigner(s_tr))
    return gate, ledger

def main(argv=None):
    ap = argparse.ArgumentParser(description="Run Claude with every tool call guarded.")
    ap.add_argument("task")
    ap.add_argument("--workdir", default=None, help="default: a new temporary directory")
    ap.add_argument("--vow", type=pathlib.Path, help="a Vow file (default: the guarded-agent Vow)")
    ap.add_argument("--ledger", help="write the ledger here")
    ap.add_argument("--max-turns", type=int, default=20)
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args(argv)
    try:
        import anthropic
    except ImportError:
        print("the anthropic package is not installed (pip install anthropic)", file=sys.stderr); return 1
    workdir = args.workdir or tempfile.mkdtemp(prefix="guarded_")
    gate, ledger = setup(workdir, args.vow.read_text() if args.vow else DEFAULT_VOW, args.ledger)
    if not gate.jail_ok:
        print(f"warning: no jail ({gate.jail_why}); shell calls will be refused", file=sys.stderr)
    try:
        agent = GuardedAgent(anthropic.Anthropic(), gate, model=args.model, max_turns=args.max_turns)
        finished, text = agent.run(args.task)
    except anthropic.AuthenticationError as e:
        print(f"the API refused the credentials: {e}", file=sys.stderr); return 1
    except anthropic.APIStatusError as e:
        print(f"the API returned {e.status_code}: {e}", file=sys.stderr); return 1
    except anthropic.APIConnectionError as e:
        print(f"could not reach the API: {e}", file=sys.stderr); return 1
    except anthropic.AnthropicError as e:
        print(f"cannot call the API: {e}", file=sys.stderr); return 1
    except TypeError as e:
        # The SDK's way of saying no credentials are configured; any other
        # TypeError is a bug and is not swallowed here.
        if "authentication method" not in str(e): raise
        print("no API credentials: set ANTHROPIC_API_KEY or run `ant auth login`", file=sys.stderr); return 1
    for name, a, outcome, detail in gate.log:
        print(f"  {outcome:16s} {name} {json.dumps(a)[:100]}")
    print(text)
    print(f"workdir: {workdir}" + (f"  ledger: {args.ledger}" if args.ledger else "")
          + f"  integrity: {'ok' if ledger.verify_integrity() else 'BROKEN'}")
    if not finished: print(f"did not finish: {text}", file=sys.stderr)
    return 0 if finished else 1

if __name__ == "__main__":
    sys.exit(main())
