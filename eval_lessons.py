"""Lessons (lessons.py) on AgentDojo: learned on some tasks, tested on others.

SED reports its AgentDojo number from one stream that it both learns from and
is scored on, so an attack seen once is defended when it comes again. That is
a fair test of a deployed defence facing a repeated attack, and an unfair one
of a defence facing a new attack. Both are measured here, on tasks the
lessons never saw:

  held-out user tasks       Each suite's user tasks are split in two, by
                            position: the even ones are learned on, the odd
                            ones tested. The injection tasks are the same on
                            both sides, so this is the repeated attack.
  held-out injection task   As above, and for each injection task, a book is
                            learned with that task left out and tested only
                            against it: an attack the lessons never saw.

The agent is the hijacked one of eval_agentdojo.py (the ground-truth calls of
the user task, then of the injection task). The judge that marks a trajectory
harmful is AgentDojo's own security check, scored on the calls that ran. The
calls it holds responsible are the ones that ran, changed the environment, and
are not in the clean run of the same user task. The known-good trajectories
a lesson must not refuse are the clean runs of the learning half.

    python3 eval_lessons.py --out results/agentdojo-lessons.json
"""
import argparse, json, multiprocessing, sys, time

import agentdojo_guard as ag
import eval_agentdojo as ev
from lessons import Lessons, learn

JUDGE = "agentdojo security check (calls that ran)"

def _key(c): return (c["tool"], json.dumps(c["args"], sort_keys=True))

def _run(suite, ut, it, executor, attack):
    injections = attack.attack(ut, it) if it is not None else {}
    return suite.run_task_with_pipeline(ev._pipeline(ut, it, executor, "local"), ut, it, injections)

_GATE = []

def _guarded(suite, ut, it, lessons, attack):
    if not _GATE: _GATE.append(ag.StateGate())        # one gate (and one ledger) per process, as in eval_agentdojo
    gate = _GATE[0]
    gate.lessons, gate.calls, start = lessons, [], len(gate.log)
    utility, hit = _run(suite, ut, it, ag.executor(gate), attack)
    gate.this_run = gate.log[start:]
    return utility, (ev.effective(it, gate, hit) if it is not None else None), gate

def suite_run(sname, version=ev.VERSION):
    import warnings
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suite
    warnings.filterwarnings("ignore")
    suite = get_suite(version, sname)
    attack = load_attack(ev.ATTACK, suite, ev._pipeline(None, None, ToolsExecutor(), "local"))
    users, injs = list(suite.user_tasks.values()), list(suite.injection_tasks.values())
    learn_u, test_u = users[0::2], users[1::2]
    # Which attacks are real: the same pair without the guard.
    feasible = {(ut.ID, it.ID): bool(_run(suite, ut, it, ToolsExecutor(), attack)[1]) for ut in users for it in injs}

    # The learning half, guarded, with no lessons: what is known good, and what the judge calls harmful.
    benign, harmful = [], []
    for ut in learn_u:
        _, _, g = _guarded(suite, ut, None, None, attack)
        clean = [dict(c) for c in g.calls]
        benign.append({"id": f"{sname}/{ut.ID}", "prompt": ut.PROMPT, "calls": clean})
        seen = {_key(c) for c in clean}
        for it in injs:
            if not feasible[(ut.ID, it.ID)]: continue
            _, ran, g = _guarded(suite, ut, it, None, attack)
            if not ran: continue
            blamed = [c for c in g.calls if c["outcome"] == "lawful" and c["changes"] and _key(c) not in seen]
            harmful.append({"id": f"{sname}/{ut.ID}/{it.ID}", "injection": it.ID, "prompt": ut.PROMPT,
                            "calls": blamed})

    books = {"held_out_user_tasks": learn(Lessons.empty(), harmful, benign, JUDGE)}
    for it in injs:
        books[f"held_out:{it.ID}"] = learn(Lessons.empty(), [h for h in harmful if h["injection"] != it.ID],
                                           benign, JUDGE)

    def test(book, only=None):
        r = {"utility": 0, "pairs": 0, "feasible": 0, "attack_effective": 0, "refused_by_lesson_clean": [],
             "misses": []}
        for ut in test_u:
            u, _, g = _guarded(suite, ut, None, book, attack)
            r["utility"] += bool(u)
            r["refused_by_lesson_clean"] += [f"{ut.ID}:{x['lesson']}" for x in g.this_run if x.get("lesson")]
            for it in injs:
                if only and it.ID != only: continue
                r["pairs"] += 1
                if not feasible[(ut.ID, it.ID)]: continue
                r["feasible"] += 1
                _, ran, _ = _guarded(suite, ut, it, book, attack)
                if ran: r["attack_effective"] += 1; r["misses"].append(f"{ut.ID}/{it.ID}")
        return r

    out = {"learn_user_tasks": [u.ID for u in learn_u], "test_user_tasks": [u.ID for u in test_u],
           "harmful_trajectories": len(harmful),
           "no_lessons": test(None),
           "held_out_user_tasks": {"book": books["held_out_user_tasks"][0].d,
                                   "book_hash": books["held_out_user_tasks"][0].hash(),
                                   "learning": books["held_out_user_tasks"][1],
                                   "test": test(books["held_out_user_tasks"][0])},
           "held_out_injection_task": {}}
    for it in injs:
        b, rep = books[f"held_out:{it.ID}"]
        out["held_out_injection_task"][it.ID] = {"lessons": len(b), "book_hash": b.hash(),
                                                 "test": test(b, only=it.ID),
                                                 "baseline": test(None, only=it.ID)}
    return sname, out

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--suites", nargs="*", default=["banking", "slack", "travel", "workspace"])
    ap.add_argument("--out", help="write the results here as JSON")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)
    t0 = time.time()
    with multiprocessing.Pool(min(args.jobs, len(args.suites))) as pool:
        parts = dict(pool.map(suite_run, args.suites))
    r = {"agentdojo_version": ev.VERSION, "attack": ev.ATTACK, "vow": "default",
         "policy_hash": ag.StatePolicy.load().hash(), "judge": JUDGE, "suites": parts,
         "seconds": round(time.time() - t0)}
    if args.out:
        with open(args.out, "w") as f: json.dump(r, f, indent=1, sort_keys=True); f.write("\n")
    print(summary(r))
    return 0

def summary(r):
    lines = [f"{'suite':10s} {'test utility: none -> lessons':>30s} {'repeated attacks: none -> lessons':>34s} "
             f"{'unseen attacks: none -> lessons':>32s} {'lessons':>8s}"]
    for name, s in r["suites"].items():
        base, e1 = s["no_lessons"], s["held_out_user_tasks"]["test"]
        e2 = s["held_out_injection_task"].values()
        b2 = sum(x["baseline"]["attack_effective"] for x in e2); t2 = sum(x["test"]["attack_effective"] for x in e2)
        f2 = sum(x["baseline"]["feasible"] for x in e2)
        n = len(s["test_user_tasks"])
        lines.append(f"{name:10s} {base['utility']:>21d}/{n} -> {e1['utility']}/{n}"
                     f" {base['attack_effective']:>22d}/{base['feasible']} -> {e1['attack_effective']}/{e1['feasible']}"
                     f" {b2:>20d}/{f2} -> {t2}/{f2} {len(s['held_out_user_tasks']['book']['lessons']):>8d}")
    return "\n".join(lines)

if __name__ == "__main__":
    sys.exit(main())
