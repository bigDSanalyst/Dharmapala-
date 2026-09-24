import importlib, os

import tests.support  # noqa: F401
import lake_critic

def test_a_lean_that_cannot_run_is_not_trusted(tmp_path, monkeypatch):
    fake = tmp_path / "lean"
    fake.write_text("#!/bin/sh\necho 'warning: noise' >&2\necho 'error: no toolchain' >&2\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    try:
        importlib.reload(lake_critic)
        assert lake_critic.which_critic() == "python-degraded"
        assert lake_critic.critic_status().endswith("does not run: error: no toolchain")
    finally:
        monkeypatch.undo(); importlib.reload(lake_critic)

def test_a_lean_that_is_not_executable_is_not_trusted(tmp_path):
    fake = tmp_path / "lean"; fake.write_text("not a program\n"); fake.chmod(0o755)
    path, why = lake_critic._probe(str(fake))
    assert path is None and "does not run" in why
