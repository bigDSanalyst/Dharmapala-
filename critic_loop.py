
import hashlib, json, pathlib, shutil, tempfile
from tools import Sandbox
from observation import observe
from vow_lean import emit_vow_compliance
from lake_critic import check, which_critic

def evidence_of(calls, workdir, predicted):
    """What a real run left behind, as data anyone can re-derive the effects
    from: every call with its result (and, for jailed shell calls, the trace
    events), the workdir, and what was predicted before it ran."""
    return {"workdir": str(workdir), "predicted": sorted(predicted),
            "calls": [[tool, kwargs, result] for tool, kwargs, result in calls]}

def evidence_digest(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()

def effects_from_evidence(evidence, reread=None):
    """The one derivation of a run's effects from its events. The executor
    uses the events jail.parse produced; a co-signer passes reread
    (witness.events_for) to replace them with its own reading of the raw trace."""
    calls = []
    for t, k, r in evidence["calls"]:
        if reread is not None and t == "shell" and isinstance(r, dict) and r.get("jailed"):
            r = dict(r, events=reread(r, k.get("cmd", "")))
        calls.append((t, k, r))
    effects = observe(calls, evidence["workdir"])
    # Reading, writing and running inside the workdir are what any plan does;
    # a real run that shows anything beyond them, unpredicted, has diverged.
    if (effects - set(evidence["predicted"])) - {"read", "write", "exec"}: effects.add("diverged")
    return effects

def execute(plan, dry_effects, workdir, jail=False):
    """Run an accepted plan for real and observe what it did. Anything the
    real run shows that the dry run did not predict is also `diverged`, so a
    Vow can forbid whatever the critic never saw. Returns (effects, calls);
    evidence_of(calls, workdir, dry_effects) is what a co-signer re-checks."""
    real = Sandbox(workdir, jail=jail)
    for tool, kwargs in plan:
        getattr(real, tool)(**kwargs)
    return effects_from_evidence(evidence_of(real.calls, real.workdir, dry_effects)), real.calls

def rehearse(plan, dry_effects, workdir=None):
    """Run the plan for real, in the jail, against a throwaway copy of the
    workdir it is meant for, and return what it did (None if the jail could
    not run it). The copy is what makes a rehearsal worth having: a script
    already in the workdir is invisible to a dry run and runs here."""
    scratch = tempfile.mkdtemp(prefix="rehearsal_")
    copy = pathlib.Path(scratch) / "work"
    try:
        if workdir and pathlib.Path(workdir).is_dir():
            shutil.copytree(workdir, copy, symlinks=True)
        else:
            copy.mkdir()
        effects, calls = execute(plan, dry_effects, str(copy), jail=True)
        if any(tool == "shell" and not result.get("jailed") for tool, _, result in calls):
            return None
        effects.discard("diverged")     # the rehearsal is the prediction, not a deviation from one
        return effects
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

class CriticLoop:
    def __init__(self, agent, vow, lake_root='/content/dharma/lean',
                 max_retries=3, verbose=True, guard=None, rehearse=False):
        # rehearse=True: before a plan is accepted it runs for real in the
        # jail against a throwaway copy of its workdir, and the critic judges
        # what that run did as well as what the dry run predicted.
        self.agent = agent; self.vow = vow; self.lake_root = lake_root
        self.max_retries = max_retries; self.verbose = verbose
        self.guard = guard; self.rehearse = rehearse
        self.attempts = []
        self.unchecked = 0      # attempts the critic could not judge at all
    def propose_and_verify(self, goal, workdir=None):
        context = ""
        for attempt in range(self.max_retries):
            dry = Sandbox(tempfile.mkdtemp(), dry_run=True)
            self.agent.sandbox = dry
            self.agent.act(goal, context=context)
            effects = observe(dry.calls, dry.workdir)
            rehearsed = None
            if self.rehearse:
                rehearsed = rehearse([(t, k) for t, k, _ in dry.calls], effects, workdir)
                if rehearsed is None:
                    # Asked to rehearse and could not: the plan is not judged.
                    self.unchecked += 1
                    self.attempts.append({"attempt": attempt + 1, "effects": sorted(effects),
                                          "accepted": False, "unchecked": "rehearsal could not run in the jail"})
                    if self.verbose: print("    critic could not judge: rehearsal could not run in the jail")
                    return set(), False, []
                effects = effects | rehearsed
            source, violations = emit_vow_compliance(effects, self.vow)
            ok, error = check(source, self.lake_root)
            if ok is None:
                # The critic did not judge this plan. Nothing may execute, and
                # nothing is recorded against the agent: it did nothing wrong.
                self.unchecked += 1
                self.attempts.append({"attempt": attempt + 1, "effects": sorted(effects),
                                      "violations": violations, "lean_ok": None,
                                      "accepted": False, "unchecked": error})
                if self.verbose: print(f"    critic could not judge: {error.splitlines()[0][:100]}")
                return set(), False, []
            lean_ok = ok
            if ok and violations:
                # Lean and Python answer the same question from the same list;
                # if they disagree, the emitter is wrong and neither is trusted.
                ok = False
                error = f"critic disagreement: lean accepted, python found {violations}"
            self.attempts.append({"attempt": attempt + 1,
                                  "effects": sorted(effects),
                                  "violations": violations, "lean_ok": lean_ok,
                                  "rehearsed": sorted(rehearsed) if rehearsed is not None else None,
                                  "accepted": ok})
            if self.verbose:
                print(f"    attempt {attempt+1}: effects={sorted(effects)}")
                if not ok:
                    first = error.splitlines()[0] if error else "(no output)"
                    print(f"      lean: {first[:100]}")
            if ok:
                plan = [(tool, kwargs) for tool, kwargs, _ in dry.calls]
                return effects, True, plan
            if self.guard is not None:
                plan = [(tool, kwargs) for tool, kwargs, _ in dry.calls]
                self.guard.record_refusal(
                    action_digest=hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(),
                    class_id="critic:" + ("+".join(violations) or "rejected"),
                    reason=f"critic rejected attempt {attempt + 1}: {error.splitlines()[0] if error else ''}",
                    notes=(f"critic: {which_critic()}",))
            if violations:
                context = (f"Your previous attempt produced forbidden effects: "
                           f"{violations}. Lean verification failed with:\n"
                           f"{error}\nTry different tool calls that do not "
                           f"produce those effects.")
            else:
                context = f"Lean verification failed:\n{error}\nTry again."
        return set(), False, []
