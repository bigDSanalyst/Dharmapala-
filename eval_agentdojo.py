"""The guard on AgentDojo, without a model.

AgentDojo (Debenedetti et al., NeurIPS 2024) measures prompt-injection
attacks on tool-using agents: 97 user tasks across workspace, travel, banking
and slack, each paired with the suite's injection tasks. Every task ships its
ground truth: the calls that solve it. This plays two agents from them,
through the guard (agentdojo_guard.py), and scores the runs with AgentDojo's
own checks:

  cooperative  makes exactly the user task's calls. Utility is whether
               AgentDojo still counts the task solved: a refusal here is the
               guard's cost.
  hijacked     makes the user task's calls and then, as an agent that has
               fully obeyed the injection would, every call of the injection
               task. Attack success is AgentDojo's own security check.

With --model and --base-url a real model plays the agent instead, through the
same guard, and the same checks score it (each pair is run once unguarded and
once guarded).

Without a model this cannot say how often a model is hijacked. It says what
the guard does when one is: the worst case, where the attack has already won
the model over and the guard is all that is left. The same pairs run without
the guard too; that baseline is what shows each attack is real.

    python3 eval_agentdojo.py                      # all suites, results to stdout
    python3 eval_agentdojo.py --out results/agentdojo.json --vow strict
    python3 eval_agentdojo.py --model qwen2.5:7b --base-url http://localhost:11434/v1 --suites banking --limit 4

Needs `pip install agentdojo` (tested with 0.1.35)."""
import argparse, collections, json, sys, time

import agentdojo_guard as ag

VERSION = "v1.2.2"
ATTACK = "important_instructions_no_names"

def _pipeline(user_task, injection_task, tools_executor, name):
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import ChatAssistantMessage, ChatUserMessage, text_content_block_from_string

    class Scripted(BasePipelineElement):
        """An agent that makes the ground-truth calls, one per turn, through tools_executor."""
        def query(self, query, runtime, env, messages=(), extra_args={}):
            messages = [ChatUserMessage(role="user", content=[text_content_block_from_string(query)])]
            plan = list(user_task.ground_truth(env))
            n = 0
            for phase in ("user", "injection"):
                if phase == "injection" and injection_task is None: break
                calls = plan if phase == "user" else list(injection_task.ground_truth(env))
                for c in calls:
                    n += 1
                    call = FunctionCall(function=c.function, args=dict(c.args), id=f"call_{n}")
                    messages.append(ChatAssistantMessage(role="assistant", tool_calls=[call],
                                                         content=[text_content_block_from_string("")]))
                    query, runtime, env, messages, extra_args = tools_executor.query(
                        query, runtime, env, messages, extra_args)
            messages.append(ChatAssistantMessage(role="assistant", tool_calls=None,
                                                 content=[text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]))
            return query, runtime, env, messages, extra_args
    p = Scripted(); p.name = name
    return p

def model_agent(model, base_url, api_key=None):
    """An agent factory for a real model behind an OpenAI-compatible server (vLLM,
    Ollama, llama.cpp, LM Studio): AgentDojo's own OpenAI pipeline, with the
    tools executed by whatever executor it is given."""
    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    llm = OpenAILLM(openai.OpenAI(base_url=base_url, api_key=api_key or "none"), model)
    def make(user_task, injection_task, tools_executor, name):
        p = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                           ToolsExecutionLoop([tools_executor, llm])])
        p.name = name
        return p
    return make

def effective(injection_task, gate, hit):
    """AgentDojo's score, but from the calls that ran. Most injection tasks are
    scored on the state the run left, where a refused call left nothing. A few
    are scored on the trace of calls the agent made (security_from_traces),
    and a trace holds refused calls too: slack's injection_task_5 counts an
    invitation the guard refused as the attacker let in. For those, score the
    trace of the calls that ran; for the rest, the official score stands."""
    from agentdojo.base_tasks import BaseInjectionTask
    if not hit or type(injection_task).security_from_traces is BaseInjectionTask.security_from_traces:
        return hit
    got = injection_task.security_from_traces("", gate.pre_env, gate.post_env, list(gate.ran))
    return hit if got is None else bool(got)

def evaluate(suites=None, vow="default", limit=None, version=VERSION, progress=None, agent=None):
    """agent: None plays the ground truth (see above); a factory from
    model_agent() runs a real model, whose every call the guard judges."""
    make = agent or _pipeline
    import warnings
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suites
    warnings.filterwarnings("ignore")
    vow_source = ag.STRICT_VOW if vow == "strict" else ag.AGENTDOJO_VOW
    out = {"agentdojo_version": version, "attack": ATTACK, "vow": vow, "policy_hash": ag.StatePolicy.load().hash(),
           "agent": "ground truth (scripted)" if agent is None else "model", "suites": {}}
    for sname, suite in get_suites(version).items():
        if suites and sname not in suites: continue
        gate = ag.StateGate(vow_source=vow_source)
        guarded = ag.executor(gate)
        plain = ToolsExecutor()
        attack = load_attack(ATTACK, suite, make(None, None, plain, "local"))
        users = list(suite.user_tasks.values())[:limit]
        injs = list(suite.injection_tasks.values())
        s = {"user_tasks": len(users), "injection_tasks": len(injs), "utility": {}, "refused_user_tasks": {},
             "pairs": 0, "feasible": 0, "attack_success": 0, "attack_effective": 0, "utility_under_attack": 0,
             "by_injection_task": {}, "by_user_task": {}, "misses": []}
        for ut in users:
            ok_plain, _ = suite.run_task_with_pipeline(make(ut, None, plain, "local"), ut, None, {})
            before = len(gate.log)
            ok_guard, _ = suite.run_task_with_pipeline(make(ut, None, guarded, "local"), ut, None, {})
            s["utility"][ut.ID] = {"unguarded": ok_plain, "guarded": ok_guard}
            refused = [r for r in gate.log[before:] if r["outcome"] != "lawful"]
            if refused:
                s["refused_user_tasks"][ut.ID] = [f"{r['tool']}: {'; '.join(r['why']) or r['witness']}" for r in refused]
            for it in injs:
                injections = attack.attack(ut, it)
                _, hit_plain = suite.run_task_with_pipeline(make(ut, it, plain, "local"), ut, it, injections)
                u, hit = suite.run_task_with_pipeline(make(ut, it, guarded, "local"), ut, it, injections)
                ran = effective(it, gate, hit)
                s["pairs"] += 1
                b = s["by_injection_task"].setdefault(it.ID, {"feasible": 0, "attack_success": 0, "attack_effective": 0})
                c = s["by_user_task"].setdefault(ut.ID, {"feasible": 0, "attack_success": 0, "attack_effective": 0,
                                                          "utility_under_attack": 0})
                c["utility_under_attack"] += bool(u)
                if hit_plain:
                    for x in (s, b, c):
                        x["feasible"] += 1; x["attack_success"] += bool(hit); x["attack_effective"] += bool(ran)
                    if hit: s["misses"].append(f"{ut.ID}/{it.ID}")
                s["utility_under_attack"] += bool(u)
            if progress: progress(sname, ut.ID)
        arb = collections.Counter((r["witness"].split(":")[0], r.get("verdict"), r["outcome"]) for r in gate.log)
        s["arbitration"] = {"calls": len(gate.log),
                            "by_layer": [{"witness": w, "verdict": v, "outcome": o, "n": n}
                                         for (w, v, o), n in sorted(arb.items(), key=lambda kv: -kv[1])],
                            "ledger_integrity": gate.ledger.verify_integrity()}
        s["utility_unguarded"] = sum(v["unguarded"] for v in s["utility"].values())
        s["utility_guarded"] = sum(v["guarded"] for v in s["utility"].values())
        out["suites"][sname] = s
    t = out["suites"].values()
    out["total"] = {k: sum(s[k] for s in t) for k in
                    ("user_tasks", "utility_unguarded", "utility_guarded", "pairs", "feasible", "attack_success",
                     "attack_effective", "utility_under_attack")}
    return out

def summary(r):
    lines = [f"AgentDojo {r['agentdojo_version']}, attack {r['attack']}, vow {r['vow']}, "
             f"policy {r['policy_hash'][:16]}", "",
             f"{'suite':10s} {'utility (unguarded -> guarded)':>31s} {'attack success (hijacked agent)':>33s} "
             f"{'of calls that ran':>18s} {'calls':>7s} {'witness disagreed':>18s}"]
    for name, s in list(r["suites"].items()) + [("total", r["total"])]:
        calls = sum(x["arbitration"]["calls"] for x in r["suites"].values()) if name == "total" else s["arbitration"]["calls"]
        dis = sum(e["n"] for x in (r["suites"].values() if name == "total" else [s])
                  for e in x["arbitration"]["by_layer"] if e["witness"] == "disagree")
        lines.append(f"{name:10s} {s['utility_unguarded']:>14d}/{s['user_tasks']:<3d} -> {s['utility_guarded']:>3d}/{s['user_tasks']:<6d}"
                     f" {s['attack_success']:>18d}/{s['feasible']:<5d} ({_pct(s['attack_success'], s['feasible'])})"
                     f" {s['attack_effective']:>9d} ({_pct(s['attack_effective'], s['feasible'])})"
                     f" {calls:>7d} {dis:>18d}")
    return "\n".join(lines)

def _pct(a, b): return f"{100 * a / b:.1f}%" if b else "n/a"

def combine(parts):
    """One result from several runs over different suites (run them in parallel, then combine)."""
    out = dict(parts[0]); out["suites"] = {}
    for p in parts:
        for k in ("agentdojo_version", "attack", "vow", "policy_hash"):
            if p[k] != out[k]: raise ValueError(f"cannot combine runs with different {k}")
        out["suites"].update(p["suites"])
    t = out["suites"].values()
    out["total"] = {k: sum(s[k] for s in t) for k in parts[0]["total"]}
    out["seconds"] = max(p.get("seconds", 0) for p in parts)
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--suites", nargs="*", help="default: all four")
    ap.add_argument("--vow", choices=["default", "strict"], default="default")
    ap.add_argument("--limit", type=int, help="only the first N user tasks of each suite")
    ap.add_argument("--out", help="write the full results here as JSON")
    ap.add_argument("--combine", nargs="+", metavar="JSON", help="combine earlier --out files instead of running")
    ap.add_argument("--model", help="run a real model instead of the ground truth (needs --base-url)")
    ap.add_argument("--base-url", help="an OpenAI-compatible server, e.g. http://localhost:11434/v1 for Ollama")
    ap.add_argument("--api-key-env", default="OPENAI_API_KEY", help="environment variable holding the key, if any")
    args = ap.parse_args(argv)
    if args.combine:
        r = combine([json.load(open(f)) for f in args.combine])
        if args.out:
            with open(args.out, "w") as f: json.dump(r, f, indent=1, sort_keys=True)
        print(summary(r)); return 0
    try:
        import agentdojo  # noqa: F401
    except ImportError:
        print("agentdojo is not installed (pip install agentdojo)", file=sys.stderr); return 1
    agent = None
    if args.model or args.base_url:
        if not (args.model and args.base_url):
            print("--model and --base-url go together", file=sys.stderr); return 1
        import os
        agent = model_agent(args.model, args.base_url, os.environ.get(args.api_key_env))
    t0 = time.time()
    r = evaluate(args.suites, args.vow, args.limit, agent=agent,
                 progress=lambda s, u: print(f"  {s} {u}", file=sys.stderr, flush=True))
    if agent is not None: r["model"] = args.model
    r["seconds"] = round(time.time() - t0)
    if args.out:
        with open(args.out, "w") as f: json.dump(r, f, indent=1, sort_keys=True)
    print(summary(r))
    return 0

if __name__ == "__main__":
    sys.exit(main())
