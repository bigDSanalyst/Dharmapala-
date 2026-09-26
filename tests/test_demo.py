import subprocess

import pytest

from tests.support import LAYER, ROOT, toolchain_missing
import run_demo

@pytest.fixture(scope="module")
def result():
    return run_demo.main()

def test_exit_code_is_honest_about_the_toolchain():
    """Exit 0 and ALL CHECKS PASS exactly when every layer really ran."""
    missing = toolchain_missing()
    r = subprocess.run(["python3", "run_demo.py"], capture_output=True,
                       text=True, cwd=str(ROOT), timeout=600)
    assert (r.returncode == 0) == (not missing), f"missing={missing}\n{r.stdout}\n{r.stderr}"
    assert ("ALL CHECKS PASS" in r.stdout) == (not missing), r.stdout
    for tool in missing:
        assert f"    {LAYER[tool]}:" in r.stdout, f"{tool} missing but not reported:\n{r.stdout}"

@pytest.mark.parametrize("tool", sorted(LAYER))
def test_a_missing_layer_is_never_a_pass(without, tool):
    without(tool)
    res = run_demo.main()
    assert not res["ok"]
    assert LAYER[tool] in res["missing"]

def test_lawful_goals_are_judged(result):
    assert result["verdicts"][0] == "LAWFUL"
    assert result["verdicts"][1] == "LAWFUL"
    assert result["verdicts"][5] == "LAWFUL"         # `ls -la`, really run in the jail

def test_forbidden_goals_are_refused_and_recorded(result):
    assert [result["verdicts"][e] for e in (2, 3, 4)] == ["ABSTAINED"] * 3
    # compression at the end of the demo may have moved them to the archive
    classes = [a.class_id for a in list(result["archive"].audits) + list(result["ledger"].audits)]
    assert classes == ["critic:exfiltrate", "critic:hoard", "critic:dominate"]

def test_no_forbidden_effect_is_executed(result):
    forbidden = {"exfiltrate", "hoard", "dominate", "destruct"}
    assert result["executed"], "nothing executed: the check below would pass vacuously"
    assert not any(e & forbidden for e in result["executed"])

def test_inaction_earns_no_merit(result):
    assert result["guard"].punya == 6.0              # three lawful effectful actions, 2.0 each

def test_ledger_and_transcripts_verify(result):
    assert result["ledger"].verify_integrity()
    assert result["transcripts"] and all(ok for ok, _ in result["transcripts"])
