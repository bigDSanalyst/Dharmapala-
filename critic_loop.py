
import hashlib, json, os, pathlib, shutil, tempfile
from cw_vfs import ConfinementViolation, clone_confined_snapshot
from tools import Sandbox, check_call, dispatch
import policy as policy_mod
from observation import observe
from vow_lean import emit_vow_compliance
from lake_critic import check, which_critic

def evidence_of(calls, workdir, predicted, policy=None, session=None):
    """What a real run left behind, as data anyone can re-derive the effects
    from: every call with its result (and, for jailed shell calls, the trace
    events), the workdir, what was predicted before it ran, and the policy
    (policy.py) that gives the effects their meaning. `session`, when the run
    was recorded by a monitor (monitor.py), is its signed session block."""
    ev = {"workdir": str(workdir), "predicted": sorted(predicted),
          "policy": policy_mod.of(policy).to_dict(),
          "calls": [[tool, kwargs, result] for tool, kwargs, result in calls]}
    if session is not None: ev["session"] = session
    return ev

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
    effects = observe(calls, evidence["workdir"], evidence.get("policy"))
    # Reading, writing and running inside the workdir are what any plan does;
    # a real run that shows anything beyond them, unpredicted, has diverged.
    if (effects - set(evidence["predicted"])) - {"read", "write", "exec"}: effects.add("diverged")
    return effects

def execute(plan, dry_effects, workdir, jail=False, policy=None, logical_workdir=None, monitor=None):
    """Run an accepted plan for real and observe what it did. Anything the
    real run shows that the dry run did not predict is also `diverged`, so a
    Vow can forbid whatever the critic never saw. Returns (effects, calls);
    evidence_of(calls, workdir, dry_effects) is what a co-signer re-checks.
    Every step is checked against the tool table before any of them runs:
    a plan with one step that is not a known tool call (UnknownCall) runs nothing.
    With a monitor, every call is recorded in its chain and the run ends on a
    signed checkpoint, whether or not it finished: monitor.last_block."""
    for tool, kwargs in plan:
        check_call(tool, kwargs)
    if monitor is not None: monitor.begin_run()
    real = (monitor.sandbox(workdir, jail=jail, logical_workdir=logical_workdir) if monitor is not None
            else Sandbox(workdir, jail=jail, logical_workdir=logical_workdir))
    try:
        for tool, kwargs in plan:
            dispatch(real, tool, kwargs)
    finally:
        real.close()
        session = monitor.end_run() if monitor is not None else None
    return effects_from_evidence(evidence_of(real.calls, real.logical_workdir, dry_effects, policy,
                                             session)), real.calls

def _rehearse_in_space(plan, dry_effects, workdir, policy, monitor):
    """rehearse(), in a copy the monitor process makes and runs (monitor.py):
    the gate's process neither reads the workdir nor starts a jail."""
    import monitor as monitor_mod
    for tool, kwargs in plan:
        check_call(tool, kwargs)
    try: space = monitor.open_space("real", "rehearsal")
    except monitor_mod.SpaceError: return None
    try:
        sb = monitor.space_sandbox(space)
        for tool, kwargs in plan:
            dispatch(sb, tool, kwargs)
    finally:
        monitor.close_space(space)
    if any(tool == "shell" and not result.get("jailed") for tool, _, result in sb.calls):
        return None
    effects = effects_from_evidence(evidence_of(sb.calls, workdir, dry_effects, policy))
    effects.discard("diverged")
    return effects

def rehearse(plan, dry_effects, workdir=None, policy=None, monitor=None):
    """Run the plan for real, in the jail, against a throwaway copy of the
    workdir it is meant for, and return what it did (None if the jail could
    not run it). The copy is what makes a rehearsal worth having: a script
    already in the workdir is invisible to a dry run and runs here. Given
    the session's monitor process, the copy is its (_rehearse_in_space)."""
    if workdir and getattr(monitor, "open_space", None) and \
            os.path.realpath(workdir) == monitor.workdir:
        return _rehearse_in_space(plan, dry_effects, workdir, policy, monitor)
    scratch = tempfile.mkdtemp(prefix="rehearsal_")
    copy = pathlib.Path(scratch) / "work"
    try:
        if workdir and pathlib.Path(workdir).is_dir():
            try: clone_confined_snapshot(workdir, copy)
            except ConfinementViolation: return None
            logical = workdir            # judged, and shown to commands, as the real workdir
        else:
            copy.mkdir(); logical = None   # nothing there yet to stand in for
        effects, calls = execute(plan, dry_effects, str(copy), jail=True,
                                 policy=policy, logical_workdir=logical)
        if any(tool == "shell" and not result.get("jailed") for tool, _, result in calls):
            return None
        effects.discard("diverged")     # the rehearsal is the prediction, not a deviation from one
        return effects
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

class CriticLoop:
    def __init__(self, agent, vow, lake_root='/content/dharma/lean',
                 max_retries=3, verbose=True, guard=None, rehearse=False, policy=None, monitor=None):
        # rehearse=True: before a plan is accepted it runs for real in the
        # jail against a throwaway copy of its workdir, and the critic judges
        # what that run did as well as what the dry run predicted.
        self.agent = agent; self.vow = vow; self.lake_root = lake_root
        self.max_retries = max_retries; self.verbose = verbose
        self.guard = guard; self.rehearse = rehearse
        self.monitor = monitor  # the session's monitor: a rehearsal runs in a copy it makes
        self.policy = policy_mod.of(policy)     # what the effects mean here (policy.py)
        self.attempts = []
        self.unchecked = 0      # attempts the critic could not judge at all
    def propose_and_verify(self, goal, workdir=None):
        context = ""
        for attempt in range(self.max_retries):
            # The dry run's directory gives its paths a workdir to be judged
            # against: nothing is written there, and it goes once they are judged.
            with tempfile.TemporaryDirectory() as nowhere:
                dry = Sandbox(nowhere, dry_run=True)
                self.agent.sandbox = dry
                self.agent.act(goal, context=context)
                effects = observe(dry.calls, dry.workdir, self.policy)
            rehearsed = None
            if self.rehearse:
                rehearsed = rehearse([(t, k) for t, k, _ in dry.calls], effects, workdir, self.policy,
                                     monitor=self.monitor)
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
