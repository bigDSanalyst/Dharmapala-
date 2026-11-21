"""A plan's calls reach the Sandbox through a fixed table (F4).

critic_loop.execute and guarded_agent's _OneCall used to run
getattr(sandbox, tool)(**kwargs), so a plan could name any attribute:
__init__ re-rooted the sandbox at a directory of the plan's choosing, and
every later step wrote there. Gate.run validates a model's call first, but
execute is called with plans from anywhere. Now both go through
tools.dispatch, which knows the four tools and exactly their arguments, and
execute checks every step before it runs any."""
import pytest

import tests.support  # noqa: F401
import guarded_agent
import tools
from critic_loop import execute
from tools import Sandbox, UnknownCall, check_call, dispatch


def test_the_table_is_the_one_the_model_is_shown():
    assert {t: set(a) for t, a in tools.TOOL_ARGS.items()} == guarded_agent.ARGS


@pytest.mark.parametrize("tool, kwargs", [
    ("file_write", {"path": "a.txt", "content": "x"}),
    ("file_read", {"path": "a.txt"}),
    ("shell", {"cmd": "true"}),
    ("http_get", {"url": "https://example.org/"}),
])
def test_each_tool_runs_through_the_table(tmp_path, tool, kwargs):
    sb = Sandbox(tmp_path)
    try:
        if tool == "file_read": (tmp_path / "a.txt").write_text("x")
        dispatch(sb, tool, kwargs)
    finally:
        sb.close()
    assert [(t, k) for t, k, _ in sb.calls] == [(tool, kwargs)]


@pytest.mark.parametrize("tool, kwargs", [
    ("__init__", {"workdir": "/elsewhere"}),
    ("_record", {"tool": "x", "kwargs": {}, "result": {}}),
    ("close", {}),
    ("calls", {}),
    ("unlink", {"path": "a.txt"}),
    ("file_write", {"path": "a.txt"}),                          # an argument missing
    ("file_write", {"path": "a.txt", "content": "x", "mode": "0777"}),   # one too many
    ("file_read", {"path": 3}),                                 # not a string
    ("file_read", ["a.txt"]),                                   # not a mapping
    (["file_read"], {"path": "a.txt"}),                         # not a name
])
def test_anything_else_is_refused(tool, kwargs):
    with pytest.raises(UnknownCall):
        check_call(tool, kwargs)


def test_a_plan_that_names_init_runs_nothing(tmp_path):
    work, elsewhere = tmp_path / "work", tmp_path / "elsewhere"
    plan = [("file_write", {"path": "first.txt", "content": "x"}),
            ("__init__", {"workdir": str(elsewhere)}),
            ("file_write", {"path": "planted.txt", "content": "x"})]
    with pytest.raises(UnknownCall):
        execute(plan, set(), str(work))
    assert not (work / "first.txt").exists()        # checked before any step ran
    assert not elsewhere.exists()


def test_the_gates_one_call_agent_goes_through_the_table(tmp_path):
    one = guarded_agent._OneCall("__init__", {"workdir": str(tmp_path / "elsewhere")})
    one.sandbox = Sandbox(tmp_path / "work", dry_run=True)
    with pytest.raises(UnknownCall):
        one.act("goal")
    assert not (tmp_path / "elsewhere").exists()
