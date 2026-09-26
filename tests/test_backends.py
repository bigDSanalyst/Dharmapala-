"""The guarded agent with a model on your own hardware.

The OpenAI-compatible backend speaks the chat-completions format that vLLM,
Ollama, llama.cpp's server and LM Studio serve. The model's side is scripted
(no model here); the gate behind it is the real one, the same the Anthropic
backend uses. The transport is tested against a real HTTP server."""
import json, os, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import tests.support  # noqa: F401
from tests.support import ROOT
import backends
import guarded_agent as ga
from tests.test_jail import needs_jail

def reply(content=None, tool_calls=None, finish="stop"):
    msg = {"role": "assistant", "content": content}
    if tool_calls is not None: msg["tool_calls"] = tool_calls
    return {"choices": [{"index": 0, "message": msg, "finish_reason": finish}]}

def call(i, name, args):
    return {"id": f"call_{i}", "type": "function",
            "function": {"name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}}

class Server:
    """Plays the model server: scripted replies in order; records every request."""
    def __init__(self, *replies): self.replies, self.requests = list(replies), []
    def __call__(self, url, payload, headers, timeout):
        self.requests.append({"url": url, "payload": json.loads(json.dumps(payload)), "headers": headers})
        return self.replies.pop(0)

def run(tmp_path, *replies, key=None, **setup):
    gate, ledger = ga.setup(tmp_path / "work", **setup)
    server = Server(*replies, reply("done"))
    backend = backends.OpenAICompatibleBackend("http://models.local/v1/", "altar", ga.SYSTEM, ga.TOOLS,
                                               api_key=key, post=server)
    finished, text = ga.GuardedAgent(backend, gate).run("do the task")
    return gate, ledger, server, finished, text

def tool_messages(server, n):
    """The role:tool messages sent with the n-th request (those added since the previous one)."""
    before = len(server.requests[n - 1]["payload"]["messages"])
    return [m for m in server.requests[n]["payload"]["messages"][before:] if m["role"] == "tool"]

# --- the request -------------------------------------------------------------------------------

def test_the_request_is_what_an_openai_compatible_server_expects(tmp_path):
    _, _, server, finished, text = run(tmp_path, key="sk-local")
    r = server.requests[0]
    assert (finished, text) == (True, "done")
    assert r["url"] == "http://models.local/v1/chat/completions"
    assert r["headers"] == {"Authorization": "Bearer sk-local"}
    p = r["payload"]
    assert p["model"] == "altar" and p["tool_choice"] == "auto"
    assert [m["role"] for m in p["messages"]] == ["system", "user"] and p["messages"][0]["content"] == ga.SYSTEM
    assert {t["function"]["name"] for t in p["tools"]} == {"shell", "file_read", "file_write", "http_get"}
    assert all(t["type"] == "function" and t["function"]["parameters"]["additionalProperties"] is False
               for t in p["tools"])

def test_no_key_no_authorization_header(tmp_path):
    _, _, server, _, _ = run(tmp_path)
    assert server.requests[0]["headers"] == {}

# --- the same gate -------------------------------------------------------------------------------

def test_lawful_calls_run_and_their_results_go_back_as_tool_messages(tmp_path):
    gate, ledger, server, finished, _ = run(tmp_path,
        reply(tool_calls=[call(1, "file_write", {"path": "n.txt", "content": "note"})], finish="tool_calls"),
        reply(tool_calls=[call(2, "file_read", {"path": "n.txt"})], finish="tool_calls"))
    assert finished
    assert tool_messages(server, 1) == [{"role": "tool", "tool_call_id": "call_1", "content": "wrote 4 bytes"}]
    assert tool_messages(server, 2) == [{"role": "tool", "tool_call_id": "call_2", "content": "note"}]
    assert [r.verdict_kind for r in ledger.records] == ["LAWFUL", "LAWFUL"] and ledger.verify_integrity()

def test_the_assistant_turn_is_kept_with_its_tool_calls(tmp_path):
    tc = [call(1, "file_write", {"path": "a", "content": "1"})]
    _, _, server, _, _ = run(tmp_path, reply(tool_calls=tc, finish="tool_calls"))
    assistant = server.requests[1]["payload"]["messages"][2]
    assert assistant == {"role": "assistant", "content": None, "tool_calls": tc}

def test_a_refusal_says_so_in_the_content(tmp_path):
    """The format has no error flag on a tool result, so the content carries it."""
    _, ledger, server, _, _ = run(tmp_path,
        reply(tool_calls=[call(1, "file_read", {"path": "/etc/shadow"})], finish="tool_calls"))
    [m] = tool_messages(server, 1)
    assert m["content"].startswith("ERROR: refused before running") and "read_sensitive_path" in m["content"]
    assert not ledger.records and ledger.audits

def test_parallel_calls_each_get_a_tool_message(tmp_path):
    _, _, server, _, _ = run(tmp_path, reply(tool_calls=[
        call(1, "file_write", {"path": "a", "content": "1"}), call(2, "file_write", {"path": "b", "content": "2"})],
        finish="tool_calls"))
    assert [m["tool_call_id"] for m in tool_messages(server, 1)] == ["call_1", "call_2"]

@pytest.mark.parametrize("raw", ['{"path": "a"', '"just a string"', "[1, 2]", ""])
def test_arguments_that_do_not_parse_are_refused_not_guessed(tmp_path, raw):
    """Local models emit broken JSON more often than hosted ones. A call whose
    arguments are not an object is refused, and nothing runs."""
    gate, ledger, server, _, _ = run(tmp_path, reply(tool_calls=[call(1, "file_write", raw)], finish="tool_calls"))
    [m] = tool_messages(server, 1)
    assert m["content"].startswith("ERROR: not a valid call")
    assert [o for _, _, o, _ in gate.log] == ["invalid"] and not ledger.records

def test_tool_calls_decide_even_when_the_server_says_stop(tmp_path):
    """Some servers report finish_reason "stop" with tool calls attached."""
    _, ledger, server, finished, _ = run(tmp_path,
        reply(tool_calls=[call(1, "file_write", {"path": "a", "content": "1"})], finish="stop"))
    assert finished and len(ledger.records) == 1 and tool_messages(server, 1)

@needs_jail
def test_a_local_models_shell_call_is_rehearsed_run_and_signed_like_any_other(tmp_path):
    _, ledger, server, _, _ = run(tmp_path,
        reply(tool_calls=[call(1, "shell", {"cmd": "echo hi > a.txt; cat a.txt"})], finish="tool_calls"),
        reply(tool_calls=[call(2, "shell", {"cmd": "printf 'cat /etc/shadow\\n' > s.sh; sh s.sh"})], finish="tool_calls"))
    [ok] = tool_messages(server, 1); [refused] = tool_messages(server, 2)
    assert ok["content"].startswith("exit 0") and "hi" in ok["content"]
    assert refused["content"].startswith("ERROR: refused before running")
    [rec] = ledger.records
    assert rec.verdict_kind == "LAWFUL" and ledger.attestations[rec.attestation_hash].evidence_digest

# --- how a turn ends ---------------------------------------------------------------------------

@pytest.mark.parametrize("r, finished, why", [
    (reply("partial", finish="length"), False, "out of output tokens"),
    (reply("", finish="content_filter"), False, "declined"),
    (reply("all done", finish="stop"), True, "all done"),
])
def test_how_a_turn_ends(tmp_path, r, finished, why):
    gate, _ = ga.setup(tmp_path / "w")
    backend = backends.OpenAICompatibleBackend("http://x/v1", "m", ga.SYSTEM, ga.TOOLS, post=Server(r))
    got = ga.GuardedAgent(backend, gate).run("task")
    assert got[0] is finished and why in got[1]

def test_a_reply_without_a_choice_is_an_error_not_a_guess(tmp_path):
    gate, _ = ga.setup(tmp_path / "w")
    backend = backends.OpenAICompatibleBackend("http://x/v1", "m", ga.SYSTEM, ga.TOOLS, post=Server({"error": "busy"}))
    with pytest.raises(backends.BackendError, match="no choice"):
        ga.GuardedAgent(backend, gate).run("task")

# --- the transport, against a real HTTP server --------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, self.headers.get("Authorization"), body))
        status, out = self.server.script.pop(0)
        data = json.dumps(out).encode() if not isinstance(out, bytes) else out
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass

@pytest.fixture
def http_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler); srv.seen, srv.script = [], []
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield srv
    srv.shutdown(); srv.server_close()

def test_the_real_transport_round_trips(tmp_path, http_server):
    http_server.script = [(200, reply(tool_calls=[call(1, "file_write", {"path": "a", "content": "x"})],
                                      finish="tool_calls")), (200, reply("done"))]
    gate, ledger = ga.setup(tmp_path / "w")
    url = f"http://127.0.0.1:{http_server.server_port}/v1"
    backend = backends.OpenAICompatibleBackend(url, "m", ga.SYSTEM, ga.TOOLS, api_key="k")
    assert ga.GuardedAgent(backend, gate).run("task") == (True, "done")
    assert [(p, a) for p, a, _ in http_server.seen] == [("/v1/chat/completions", "Bearer k")] * 2
    assert (tmp_path / "w" / "a").read_text() == "x"

@pytest.mark.parametrize("status, body, why", [(500, {"error": "boom"}, "returned 500"),
                                               (200, b"<html>not json", "not JSON")])
def test_a_server_error_is_named(tmp_path, http_server, status, body, why):
    http_server.script = [(status, body)]
    gate, _ = ga.setup(tmp_path / "w")
    backend = backends.OpenAICompatibleBackend(f"http://127.0.0.1:{http_server.server_port}/v1", "m",
                                               ga.SYSTEM, ga.TOOLS)
    with pytest.raises(backends.BackendError, match=why):
        ga.GuardedAgent(backend, gate).run("task")

# --- the command line --------------------------------------------------------------------------

def cli(tmp_path, *args):
    return subprocess.run([sys.executable, str(ROOT / "guarded_agent.py"), "task", "--workdir", str(tmp_path / "w"),
                           *args], capture_output=True, text=True, timeout=120)

def test_the_command_line_needs_a_url_and_a_model(tmp_path):
    r = cli(tmp_path, "--backend", "openai-compatible", "--model", "m")
    assert r.returncode == 1 and "--base-url and --model" in r.stderr and "Traceback" not in r.stderr

def test_the_command_line_names_an_unreachable_server(tmp_path):
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()   # nothing listens
    r = cli(tmp_path, "--backend", "openai-compatible", "--model", "m", "--base-url", f"http://127.0.0.1:{port}/v1")
    assert r.returncode == 1 and "could not reach the model server" in r.stderr and "Traceback" not in r.stderr

def test_the_command_line_runs_against_a_local_server(tmp_path, http_server):
    http_server.script = [(200, reply(tool_calls=[call(1, "file_write", {"path": "a", "content": "x"})],
                                      finish="tool_calls")), (200, reply("finished the task"))]
    r = cli(tmp_path, "--backend", "openai-compatible", "--model", "altar",
            "--base-url", f"http://127.0.0.1:{http_server.server_port}/v1")
    assert r.returncode == 0, r.stderr
    assert "lawful" in r.stdout and "finished the task" in r.stdout and "integrity: ok" in r.stdout
    assert http_server.seen[0][2]["model"] == "altar"
