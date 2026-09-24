
from effects import EFFECTS as EFFECT_NAMES, require_known

def emit_vow_compliance(effects, vow):
    forbidden = [c.arg1 for c in vow.action_clauses() if c.op.name == "FORBID"]
    present = sorted(e for e in effects if e in EFFECT_NAMES)
    violations = [f for f in forbidden if f in effects]
    lines = ["inductive Effect where",
             "  | " + " | ".join(EFFECT_NAMES),
             "  deriving DecidableEq, Repr", "", "open Effect", ""]
    effects_lean = ", ".join(f"Effect.{e}" for e in present) if present else ""
    lines.append(f"def proposedEffects : List Effect := [{effects_lean}]")
    lines.append("")
    for f in forbidden:
        require_known(f, f"vow {vow.name}")
        lines.append(f"example : Effect.{f} \u2209 proposedEffects := by decide")
        lines.append("")
    return "\n".join(lines), violations
