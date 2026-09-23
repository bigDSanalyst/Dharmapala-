import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def test_end_to_end():
    """The demo must run and print the success line."""
    r = subprocess.run(
        ["python3", "run_demo.py"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=300)
    assert r.returncode == 0, f"demo failed:\n{r.stdout}\n{r.stderr}"
    assert "ALL CHECKS PASS" in r.stdout
