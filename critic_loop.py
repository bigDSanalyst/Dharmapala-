
import tempfile
from tools import Sandbox
from observation import observe
from vow_lean import emit_vow_compliance
from lake_critic import check, which_critic

class CriticLoop:
    def __init__(self, agent, vow, lake_root='/content/dharma/lean',
                 max_retries=3, verbose=True, guard=None):
        self.agent = agent; self.vow = vow; self.lake_root = lake_root
        self.max_retries = max_retries; self.verbose = verbose
        self.guard = guard
        self.attempts = []
    def propose_and_verify(self, goal):
        context = ""
        for attempt in range(self.max_retries):
            dry = Sandbox(tempfile.mkdtemp(), dry_run=True)
            self.agent.sandbox = dry
            self.agent.act(goal, context=context)
            effects = observe(dry.calls, dry.workdir)
            source, violations = emit_vow_compliance(effects, self.vow)
            ok, error = check(source, self.lake_root)
            lean_ok = ok
            if ok and violations:
                # Lean and Python answer the same question from the same list;
                # if they disagree, the emitter is wrong and neither is trusted.
                ok = False
                error = f"critic disagreement: lean accepted, python found {violations}"
            self.attempts.append({"attempt": attempt + 1,
                                  "effects": sorted(effects),
                                  "violations": violations, "lean_ok": lean_ok,
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
                self.guard.record_refusal(
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
