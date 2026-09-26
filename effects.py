
# The one list of effect names. observation.py emits only these, parse_vow
# accepts only these in commit/forbid clauses, vow_lean.py emits them as Lean
# constructors, and lean/Dharma/Effects.lean declares the same set
# (tests/test_vocabulary.py fails if any copy drifts).
EFFECTS = ("read", "write", "exfiltrate", "hoard", "dominate",
           "destruct", "network_access", "exec", "read_sensitive_path",
           "read_outside_workdir", "write_outside_workdir", "exec_unvetted",
           "network_unlisted", "diverged")

class UnknownEffect(ValueError): pass

def require_known(name, where):
    if name not in EFFECTS:
        raise UnknownEffect(f"{where}: unknown effect {name!r}; known: {', '.join(EFFECTS)}")
    return name
