
# The model side of the guarded agent, one class per wire format.
#
# The gate never sees a provider: it is handed (call id, tool name, arguments)
# and returns (content, is_error). A backend owns the conversation in its
# provider's own shape and translates at the edges, so a model is only ever a
# source of proposed calls, whoever serves it:
#
#   AnthropicBackend         Claude through the Anthropic API
#   OpenAICompatibleBackend  anything that speaks the OpenAI chat-completions
#                            API with tools: vLLM, Ollama, llama.cpp's server,
#                            LM Studio. A model served on your own hardware
#                            keeps what lawful calls return inside your network.
#
# step() returns a Turn. A call whose arguments did not parse is still passed
# on, with args=None, so the gate refuses it and says so; nothing is guessed.
import json, urllib.error, urllib.request
from dataclasses import dataclass, field

DONE, TOOL_USE, PAUSE, MAX_TOKENS, REFUSAL = "done", "tool_use", "pause", "max_tokens", "refusal"

@dataclass
class Turn:
    stop: str                                   # one of the five above
    text: str = ""
    calls: list = field(default_factory=list)   # [(call_id, name, args or None)]

class BackendError(Exception): pass

class AnthropicBackend:
    """Claude, through the Anthropic SDK's beta messages endpoint."""
    FALLBACK_BETA = "server-side-fallback-2026-07-01"

    def __init__(self, client, model, system, tools, max_tokens=16000):
        self.client, self.model, self.system, self.max_tokens = client, model, system, max_tokens
        self.tools = [{"name": t["name"], "description": t["description"], "strict": True,
                       "input_schema": t["input_schema"]} for t in tools]
        self.messages = []

    def start(self, task): self.messages = [{"role": "user", "content": task}]

    def step(self):
        r = self.client.beta.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=self.system, tools=self.tools,
            thinking={"type": "adaptive"}, messages=self.messages,
            betas=[self.FALLBACK_BETA], fallbacks="default")
        if r.stop_reason == "refusal": return Turn(REFUSAL)
        self.messages.append({"role": "assistant", "content": r.content})
        text = "".join(b.text for b in r.content if b.type == "text")
        stop = {"pause_turn": PAUSE, "max_tokens": MAX_TOKENS, "tool_use": TOOL_USE}.get(r.stop_reason, DONE)
        calls = [(b.id, b.name, b.input if isinstance(b.input, dict) else None)
                 for b in r.content if b.type == "tool_use"] if stop == TOOL_USE else []
        return Turn(stop, text, calls)

    def reply(self, results):
        """results: [(call_id, content, is_error)], all in one message."""
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": i, "content": c, "is_error": e} for i, c, e in results]})

def _http_post(url, payload, headers, timeout):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise BackendError(f"the model server returned {e.code}: {body}") from None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        raise BackendError(f"could not reach the model server at {url}: {getattr(e, 'reason', e)}") from None
    except ValueError as e:
        raise BackendError(f"the model server's reply is not JSON: {e}") from None

class OpenAICompatibleBackend:
    """Any server speaking OpenAI-style chat completions with tool calls."""

    def __init__(self, base_url, model, system, tools, api_key=None, max_tokens=16000,
                 timeout=600, post=None):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model, self.system, self.max_tokens, self.timeout = model, system, max_tokens, timeout
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                         "parameters": t["input_schema"]}} for t in tools]
        self._post = post or _http_post
        self.messages = []

    def start(self, task):
        self.messages = [{"role": "system", "content": self.system}, {"role": "user", "content": task}]

    def step(self):
        r = self._post(self.url, {"model": self.model, "messages": self.messages, "tools": self.tools,
                                  "tool_choice": "auto", "max_tokens": self.max_tokens},
                       self.headers, self.timeout)
        try:
            choice = r["choices"][0]; msg = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise BackendError(f"the model server's reply has no choice: {json.dumps(r)[:200]}") from None
        finish = choice.get("finish_reason")
        tool_calls = msg.get("tool_calls") or []
        kept = {"role": "assistant", "content": msg.get("content")}
        if tool_calls: kept["tool_calls"] = tool_calls
        self.messages.append(kept)
        text = msg.get("content") or ""
        if finish == "content_filter": return Turn(REFUSAL, text)
        # Some servers say "stop" with tool calls attached: the calls decide.
        if tool_calls: return Turn(TOOL_USE, text, [self._call(c) for c in tool_calls])
        if finish == "length": return Turn(MAX_TOKENS, text)
        return Turn(DONE, text)

    @staticmethod
    def _call(c):
        # Arguments arrive as a JSON string. Whatever it decodes to goes to the
        # gate, which refuses anything but an object with exactly the tool's
        # fields; a string that does not decode goes as None and is refused too.
        fn = c.get("function") or {}
        raw = fn.get("arguments")
        try: args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError: args = None
        return c.get("id") or "", fn.get("name") or "", args

    def reply(self, results):
        # The format has no error flag on a tool result, so the content says it.
        for i, c, e in results:
            self.messages.append({"role": "tool", "tool_call_id": i,
                                  "content": f"ERROR: {c}" if e else c})
