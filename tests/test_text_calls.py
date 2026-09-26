"""A tool call written into the answer as text is named, never run.

In the second live run a 7B model, asked to read a file back to confirm a
write, put the call into its answer as text instead of making it. The loop
saw no call, the turn ended, and the answer looked like work in progress.
Nothing ran; the account showed two calls. The report now also says what
the text was."""
import json, subprocess, sys, threading
from http.server import HTTPServer

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
from guarded_agent import tool_calls_in_text
from tests.test_backends import _Handler, call, reply

COLAB = 'portunals\n{"name": "file_read", "arguments": {"path": "notes.txt"}}\n</tool_call>'

@pytest.mark.parametrize("text, found", [
    (COLAB, [("file_read", {"path": "notes.txt"})]),
    ('Next I will run:\n```json\n{"name": "shell", "parameters": {"cmd": "ls"}}\n```',
     [("shell", {"cmd": "ls"})]),
    ('{"name": "file_write", "input": {"path": "a", "content": "x"}} then '
     '{"name": "file_read", "arguments": {"path": "a"}}',
     [("file_write", {"path": "a", "content": "x"}), ("file_read", {"path": "a"})]),
    ("<tool_call>\nread the notes\n</tool_call>", [("?", None)]),
    ('Let {me} check the file: {"name": "file_read", "arguments": {"path": "notes.txt"}}',   # a stray brace first
     [("file_read", {"path": "notes.txt"})]),
    ('{"name": "file_read", "arguments": "notes.txt"}', [("file_read", None)]),
])
def test_calls_written_as_text_are_found(text, found):
    assert tool_calls_in_text(text) == found

@pytest.mark.parametrize("text", [
    "notes.txt now reads alpha, beta and gamma.",
    '{"name": "Ada", "arguments": "none"}',                  # not a tool
    '{"name": "file_read", "path": "notes.txt"}',             # a tool, but no arguments key
    "a { stray brace and a } closing one",
    "",
])
def test_an_ordinary_answer_is_not_flagged(text):
    assert tool_calls_in_text(text) == []

def test_the_report_names_them_and_nothing_runs(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), _Handler); srv.seen = []
    srv.script = [(200, reply(tool_calls=[call(1, "file_write", {"path": "notes.txt", "content": "alpha\nbeta\ngamma"})],
                              finish="tool_calls")),
                  (200, reply(COLAB))]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        work = tmp_path / "w"; work.mkdir()
        r = subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(work),
                            "--ledger", str(tmp_path / "l.json"), "--backend", "openai-compatible",
                            "--model", "m", "--base-url", f"http://127.0.0.1:{srv.server_port}/v1"],
                           capture_output=True, text=True, timeout=120)
    finally: srv.shutdown(); srv.server_close()
    assert r.returncode == 0, r.stderr
    assert "note: the model wrote 1 tool call(s) as text instead of making them (file_read notes.txt); " \
           "they were not run" in r.stdout
    entries = [json.loads(l) for l in (tmp_path / "l.json.runs.jsonl").read_text().splitlines()]
    assert [(e["tool"], e["outcome"]) for e in entries] == [("file_write", "lawful")]
