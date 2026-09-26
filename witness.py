
# The co-signer's own reading of a jailed run's raw trace.
#
# jail.parse is how the guard's side turns strace output into events. If the
# co-signer re-derived effects from the events jail.parse produced, a bug in
# jail.parse (or a guard that ran a doctored one) would be vouched for by both
# signatures. So the run record carries the raw per-process trace too, and the
# co-signer parses it here: a second implementation, written separately and
# differently. jail.parse finds its fields with regexes over the whole line;
# this splits each call into positional arguments with a small tokenizer and
# reads each argument where the syscall's signature puts it. The two must
# agree on every honest run (tests/test_witness.py) and share no code, so a
# fault in one shows up as a disagreement, and a disagreement is a refusal.
#
# What it shares with the guard is the vocabulary: its events have the same
# shape as jail.parse's, and effects are named by jail.effects_of. The mapping
# from events to Vow effects is the Vow's, not either parser's.
import os

_CLONES = {"clone", "clone3", "fork", "vfork"}
_OPENS = {"openat": 1, "open": 0, "creat": 0}          # syscall -> index of the path argument
_UNLINKS = {"unlinkat": (0, 1), "unlink": (None, 0)}   # (dirfd index, path index)
_RENAMES = {"renameat": ((0, 1), (2, 3)), "renameat2": ((0, 1), (2, 3)),
            "rename": ((None, 0), (None, 1))}
_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "a": "\a", "b": "\b",
            "\\": "\\", '"': '"', "'": "'", "?": "?"}

def _string(s, i):
    """s[i] is a double quote. Returns (the decoded C string, index after it)."""
    out, i = [], i + 1
    while i < len(s):
        c = s[i]
        if c == '"': return "".join(out), i + 1
        if c != "\\": out.append(c); i += 1; continue
        n = s[i + 1] if i + 1 < len(s) else ""
        if n == "x":
            out.append(chr(int(s[i + 2:i + 4], 16))); i += 4
        elif n.isdigit():
            j = i + 1
            while j < len(s) and j < i + 4 and s[j] in "01234567": j += 1
            out.append(chr(int(s[i + 1:j], 8))); i = j
        else:
            out.append(_ESCAPES.get(n, n)); i += 2
    raise ValueError("unterminated string")

def _split(line):
    """'name(a, b, ...) = ret rest' -> (name, [arg, ...], ret, rest), each arg
    a list of pieces: decoded strings as ('s', text), everything else as ('t', text).
    None for anything that is not a completed call (signals, exits, resumptions)."""
    line = line.strip()
    k = line.find("(")
    if k <= 0 or not line[:k].isidentifier(): return None
    name, i, depth = line[:k], k + 1, 0
    args, cur, text = [], [], []
    def flush_text():
        if text: cur.append(("t", "".join(text))); text.clear()
    while i < len(line):
        c = line[i]
        if c == '"':
            flush_text(); val, i = _string(line, i); cur.append(("s", val))
            if line.startswith("...", i): i += 3          # truncated by -s
            continue
        if c in "([{<": depth += 1
        elif c in ")]}>":
            if depth == 0 and c == ")":
                flush_text(); args.append(cur); i += 1; break
            depth -= 1
        if c == "," and depth == 0:
            flush_text(); args.append(cur); cur = []; i += 1
            while i < len(line) and line[i] == " ": i += 1
            continue
        text.append(c); i += 1
    else:
        return None                                        # never closed: not a whole call
    rest = line[i:].lstrip()
    if not rest.startswith("="): return None
    ret_and_more = rest[1:].strip()
    ret = ret_and_more.split(None, 1)[0] if ret_and_more else "?"
    tail = ret_and_more[len(ret):]
    # the return value may carry the fd's resolved path: 3</etc/shadow>
    if "<" in ret and not ret.startswith("<"):
        ret, _, annot = ret.partition("<"); tail = "<" + annot + tail
    return name, args, ret, tail

def _strings(arg): return [v for kind, v in arg if kind == "s"]
def _text(arg): return "".join(v for kind, v in arg if kind == "t")

def _fd_path(arg):
    """AT_FDCWD</work> or 5</proc/653> -> '/work' (None when not annotated)."""
    t = _text(arg)
    a, b = t.find("<"), t.rfind(">")
    return t[a + 1:b] if 0 <= a < b else None

def _succeeded(ret): return ret not in ("?", "") and not ret.startswith("-")

def _resolve(dirfd_arg, path, tail, succeeded):
    if succeeded and tail.startswith("<"):
        end = tail.find(">")
        if end > 0: return tail[1:end]
    if not path.startswith("/"):
        base = _fd_path(dirfd_arg) if dirfd_arg is not None else None
        if base is None: return path
        path = os.path.join(base, path)
    return os.path.realpath(path)

def _argv(arg):
    return tuple(_strings(arg))

def parse(per_pid, cmd):
    """{pid: raw strace text} -> [(kind, detail, succeeded)], or None when no
    process ever became `sh -c cmd`. Same contract as jail.parse, separately built."""
    calls = {}
    for pid, text in per_pid.items():
        parsed = []
        for line in text.split("\n"):
            try: c = _split(line)
            except (ValueError, IndexError): c = None
            if c: parsed.append(c)
        calls[int(pid)] = parsed
    def is_root_exec(name, args, ret):
        return name == "execve" and ret == "0" and len(args) > 1 and _argv(args[1])[:3] == ("sh", "-c", cmd)
    root = next((pid for pid, cs in calls.items() if any(is_root_exec(n, a, r) for n, a, r, _ in cs)), None)
    if root is None: return None

    events, queue, done = [], [(root, True)], set()
    while queue:
        pid, is_root = queue.pop(0)
        if pid in done or pid not in calls: continue
        done.add(pid)
        live = not is_root                 # the root counts only from its exec of sh -c
        for name, args, ret, tail in calls[pid]:
            ok = _succeeded(ret)
            if not live:
                live = name == "execve" and ok and len(args) > 1 and _argv(args[1])[:2] == ("sh", "-c")
                continue
            if name in _CLONES:
                marker = "in strace's PID NS"
                if ok and marker in tail:
                    host = tail.split("/*", 1)[1].split(marker, 1)[0].strip()
                    if host.isdigit(): queue.append((int(host), False))
            elif name == "execve":
                if ok and len(args) > 1: events.append(("exec", _argv(args[1]), True))
            elif name in _OPENS:
                at = _OPENS[name]
                if len(args) > at and _strings(args[at]):
                    flags = set(_text(args[at + 1]).split("|")) if len(args) > at + 1 else set()
                    write = name == "creat" or bool(flags & _WRITE_FLAGS)
                    dirfd = args[0] if name == "openat" else None
                    events.append(("write" if write else "read",
                                   _resolve(dirfd, _strings(args[at])[0], tail, ok), ok))
            elif name == "connect":
                if len(args) < 2: continue
                addr = args[1]
                if "sa_family=AF_UNIX" in _text(addr): continue
                t = _text(addr); ips = _strings(addr)
                if ("inet_addr(" in t or "inet_pton(" in t) and ips:
                    events.append(("connect", ips[-1], ok))
                else:
                    events.append(("connect", _text(args[0]) + ", " + t, ok))
            elif name in _UNLINKS:
                d, p = _UNLINKS[name]
                if len(args) > p and _strings(args[p]):
                    events.append(("unlink", _resolve(args[d] if d is not None else None,
                                                      _strings(args[p])[0], "", False), ok))
            elif name in _RENAMES:
                (d1, p1), (d2, p2) = _RENAMES[name]
                if len(args) > p2 and _strings(args[p1]) and _strings(args[p2]):
                    events.append(("rename", (
                        _resolve(args[d1] if d1 is not None else None, _strings(args[p1])[0], "", False),
                        _resolve(args[d2] if d2 is not None else None, _strings(args[p2])[0], "", False)), ok))
            elif name == "kill":
                if args: events.append(("kill", _text(args[0]).strip(), ok))
    return events

class Unreadable(Exception): pass

def events_for(result, cmd):
    """The events of one jailed shell call, read from its raw trace. Refuses
    rather than falling back to the events the guard's side supplied."""
    trace = result.get("trace")
    if not isinstance(trace, dict) or not trace:
        raise Unreadable("a jailed call carries no raw trace")
    events = parse(trace, cmd)
    if events is None:
        raise Unreadable("the raw trace never shows the command starting")
    return events
