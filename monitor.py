# The monitor's record of a session: what P0 signs (docs/monitor-boundary.md, section 5).
#
# A capability witness proves that a file call was confined beneath some root,
# but not which one: a well-formed witness from any directory verified (F3).
# The monitor is what holds the workdir, so it states the root once, in a
# session header it signs, and records every real call in a hash chain whose
# head it signs at the end of each run. A co-signer, and verify.py later,
# check a run's witnesses against the header and its calls against the chain.
#
# The monitor runs as its own process (Phase 2, slice 2; serve() below): it
# holds the key and the workdir's descriptor, runs every real call, and
# parses nothing it did not write but the gate's request frames. The gate
# (P1) talks to it through RemoteMonitor and never holds its key. Monitor is
# the record itself, used inside that process, or inside the gate's own
# process when no publicly verifiable signature scheme is installed.
#
#   header      {v, session, workdir, root: [dev, ino], resolve_mask,
#                policy_hash, vow_hash, monitor_code_hash, monitor_key_id, start}
#   record i    {index, prev, session, op, args_sha256, result_sha256, time}
#               result_sha256 is over the result as the monitor produced it:
#               without "events", which the gate derives from the raw trace
#   checkpoint  {session, index, head}: the last record's index and hash
#
# Each is canonical JSON (sorted keys, no spaces), and each signature is over
# that encoding. Refusals go to a stream of their own, the quarantine stream
# (Quarantine, below), never into this record.
#
# A run's evidence carries a "session" block: the signed header,
# the checkpoint the run started from (None for the first), the run's records
# and the checkpoint it ended on.
import hashlib, json, os, secrets, stat, time

GENESIS = "0" * 64
CODE = ("monitor.py", "tools.py", "cw_vfs.py", "jail.py", "confine.py")

def canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))
def sha(obj): return hashlib.sha256(canon(obj).encode()).hexdigest()
DERIVED = ("events",)
def result_sha(result):
    if isinstance(result, dict): result = {k: v for k, v in result.items() if k not in DERIVED}
    return sha(result)

def code_hash():
    """The monitor's code: what a header says it ran."""
    here, h = os.path.dirname(os.path.abspath(__file__)), hashlib.sha256()
    for name in CODE:
        with open(os.path.join(here, name), "rb") as f: data = f.read()
        h.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()

def root_of(workdir):
    """(realpath, dev, ino) of the workdir, read the way cw_vfs pins it."""
    path = os.path.realpath(workdir)
    os.makedirs(path, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode): raise ValueError(f"{path} is not a directory")
        return path, st.st_dev, st.st_ino
    finally:
        os.close(fd)

# The quarantine stream (docs/monitor-boundary.md, section 5): what was refused
# in a session, kept apart from its record, so that a refusal adds nothing to
# what the session is held to. The monitor appends its own cw_vfs refusals
# and the Vow and guard refusals the gate reports. It parses none of what it
# keeps: it clips it, hashes it, chains it and signs a checkpoint over the
# head at every append. The stream is written under quarantine/<session>/
# when the monitor is given a directory, and is kept in memory otherwise.
#
#   record      {v, session, q_index, prev_q_hash, time, terminal_mode,
#                trigger: {layer, reason, call_json, call_sha256, context_sha256,
#                          record_index},
#                artifacts, kernel_telemetry, pivot_chain}
#   checkpoint  {session, q_index, head, terminal_mode, dropped}
#
# call_json is the refused call, kept up to Q_FIELD bytes; call_sha256 is over
# all of it. record_index is the session record of a call the monitor ran and
# refused (None for a refusal the gate reports). Past Q_MAX records, further
# refusals are only counted (dropped). artifacts, kernel_telemetry and
# pivot_chain are empty: nothing fills them yet.
LAYERS = ("vow", "guard", "ipc", "cw_vfs", "jail")
REPORTED = ("vow", "guard")          # what the gate may report; the rest are the monitor's own
Q_MAX = 1000
Q_FIELD = 4096
Q_REASON = 128

def _clip(text, n):
    data = text.encode("utf-8")
    return text if len(data) <= n else data[:n].decode("utf-8", "ignore")

def _now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _within(a, b):
    return a == b or a.startswith(b.rstrip("/") + "/")

class QuarantineError(ValueError):
    """The quarantine directory cannot be the session's: it overlaps the workdir."""

class Quarantine:
    def __init__(self, session, sign, folder=None):
        self.session, self._sign = session, sign
        self.records, self.dropped, self.mode = [], 0, "live"
        self.checkpoint = None
        self.dir = None
        if folder is not None:
            self.dir = os.path.join(folder, session)
            os.makedirs(self.dir, mode=0o700)        # a new session's; never one already there
        self._seal(None)                 # an empty stream is signed too: a session with nothing refused
    def head(self): return sha(self.records[-1]) if self.records else GENESIS
    def _seal(self, rec):
        cp = {"session": self.session, "q_index": len(self.records) - 1, "head": self.head(),
              "terminal_mode": self.mode, "dropped": self.dropped}
        self.checkpoint = dict(cp, signature=self._sign(cp))
        if self.dir is not None: self._write(rec)
    def add(self, layer, reason, call_json, context_sha256="", record_index=None):
        """Append a refusal. (record, checkpoint); the record is None once
        the stream is full, and the refusal is only counted."""
        if layer not in LAYERS: raise ValueError(f"no layer {layer!r}")
        rec = None
        if len(self.records) >= Q_MAX:
            self.dropped += 1
        else:
            rec = {"v": 1, "session": self.session, "q_index": len(self.records), "prev_q_hash": self.head(),
                   "time": _now(), "terminal_mode": self.mode,
                   "trigger": {"layer": layer, "reason": _clip(reason, Q_REASON),
                               "call_json": _clip(call_json, Q_FIELD),
                               "call_sha256": hashlib.sha256(call_json.encode("utf-8")).hexdigest(),
                               "context_sha256": context_sha256, "record_index": record_index},
                   "artifacts": [],
                   "kernel_telemetry": {"trace_sha256": None, "trace_ref": None, "strace_seccomp_bpf": False},
                   "pivot_chain": []}
            self.records.append(rec)
        self._seal(rec)
        return rec, self.checkpoint
    def _write(self, rec):
        if rec is not None:
            with open(os.path.join(self.dir, "records.jsonl"), "a") as f:
                f.write(canon(rec) + "\n"); f.flush(); os.fsync(f.fileno())
        tmp = os.path.join(self.dir, ".checkpoint.json")
        with open(tmp, "w") as f:
            f.write(canon(self.checkpoint)); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, os.path.join(self.dir, "checkpoint.json"))

def load_quarantine(folder):
    """(records, checkpoint) of the stream written under `folder` (a session's)."""
    try:
        with open(os.path.join(folder, "records.jsonl")) as f: records = [json.loads(l) for l in f if l.strip()]
    except FileNotFoundError: records = []
    with open(os.path.join(folder, "checkpoint.json")) as f: checkpoint = json.load(f)
    return records, checkpoint

class Monitor:
    def __init__(self, signer, workdir, policy_hash="", vow_hash="", resolve_mask=None, quarantine=None):
        from signing import verifier_for
        import cw_vfs
        path, dev, ino = root_of(workdir)
        if quarantine is not None:
            q = os.path.realpath(quarantine)
            if _within(q, path) or _within(path, q):
                raise QuarantineError(f"the quarantine directory {q} overlaps the workdir {path}")
        self._signer = signer
        self.header = {"v": 1, "session": secrets.token_hex(16), "workdir": path, "root": [dev, ino],
                       "resolve_mask": cw_vfs.RESOLVE_STRICT_MASK if resolve_mask is None else resolve_mask,
                       "policy_hash": policy_hash, "vow_hash": vow_hash,
                       "monitor_code_hash": code_hash(),
                       "monitor_key_id": verifier_for(signer).key_id(),
                       "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.header_signature = self._sign(self.header)
        self.records = []
        self._checkpoint = None           # the last one signed
        self._run_from = 0                # the first record after it
        self.last_block = None            # the session block of the last run
        self.quarantine = Quarantine(self.session, self._sign, quarantine)
        self.quarantined = None           # (record, checkpoint) of the last call's refusal
    @property
    def verifier(self):
        from signing import verifier_for
        return verifier_for(self._signer)
    def sandbox(self, workdir, jail=False, logical_workdir=None):
        from tools import Sandbox
        return Sandbox(workdir, jail=jail, logical_workdir=logical_workdir, monitor=self)
    @property
    def session(self): return self.header["session"]
    def head(self): return sha(self.records[-1]) if self.records else GENESIS
    def _sign(self, obj): return self._signer.sign(canon(obj).encode()).hex()

    def record(self, op, kwargs, result):
        r = {"index": len(self.records), "prev": self.head(), "session": self.session, "op": op,
             "args_sha256": sha(kwargs), "result_sha256": result_sha(result),
             "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.records.append(r)
        # A file call cw_vfs refused: a missing file, a ../ path and a path
        # outside the workdir all come back as these (decision 5).
        if op in ("file_read", "file_write") and isinstance(result, dict) and result.get("ok") is False:
            self.quarantined = self.quarantine.add("cw_vfs", result.get("code") or "error",
                                                   canon({"op": op, "args": kwargs}), record_index=r["index"])
        return r

    def report_refusal(self, layer, reason, call, context=""):
        """A refusal the gate decided (a Vow or guard refusal), into the stream."""
        if layer not in REPORTED: raise ValueError(f"the gate does not report {layer!r} refusals")
        return self.quarantine.add(layer, reason, call, context)
    @property
    def quarantine_records(self): return self.quarantine.records
    @property
    def quarantine_checkpoint(self): return self.quarantine.checkpoint

    def begin_run(self): pass      # a run is everything since the last checkpoint

    def end_run(self):
        """Sign a checkpoint over the head and return the run's session block:
        every record since the last checkpoint, so none is ever left out."""
        before = self._checkpoint
        cp = {"session": self.session, "index": len(self.records) - 1, "head": self.head()}
        self._checkpoint = dict(cp, signature=self._sign(cp))
        self.last_block = {"header": self.header, "header_signature": self.header_signature,
                           "from_checkpoint": before, "records": self.records[self._run_from:],
                           "checkpoint": self._checkpoint}
        self._run_from = len(self.records)
        return self.last_block

class SessionError(ValueError): pass

def _verify(verifier, obj, sig_hex):
    try: sig = bytes.fromhex(sig_hex)
    except (TypeError, ValueError): return False
    return verifier.verify(canon(obj).encode(), sig)

def _checkpoint_ok(verifier, cp, session):
    if not isinstance(cp, dict): return False
    body = {k: cp.get(k) for k in ("session", "index", "head")}
    return body["session"] == session and _verify(verifier, body, cp.get("signature"))

def check_quarantine(records, checkpoint, verifier, session):
    """Raise SessionError unless `records` are a session's whole quarantine
    stream: chained from the first, in order, and ending at `checkpoint`,
    which `verifier` (the session's monitor) signed."""
    prev = GENESIS
    for i, r in enumerate(records):
        if not isinstance(r, dict) or r.get("q_index") != i or r.get("prev_q_hash") != prev \
                or r.get("session") != session or (r.get("trigger") or {}).get("layer") not in LAYERS:
            raise SessionError(f"quarantine record {i} is not the next one of this session's")
        prev = sha(r)
    body = {k: checkpoint.get(k) for k in ("session", "q_index", "head", "terminal_mode", "dropped")} \
        if isinstance(checkpoint, dict) else None
    if body is None or body["session"] != session or body["q_index"] != len(records) - 1 \
            or body["head"] != prev or not _verify(verifier, body, checkpoint.get("signature")):
        raise SessionError("the quarantine checkpoint does not sign these records")

def check_block(block, verifier, workdir=None, calls=None, policy_hash=None):
    """Raise SessionError unless `block` holds: the header and both checkpoints
    are signed by `verifier`, the records chain from the starting checkpoint to
    the ending one, and (given `calls`) the records are exactly those calls.
    With `workdir`, the header must be for it. Returns the header."""
    if not isinstance(block, dict): raise SessionError("no session block")
    header = block.get("header")
    if not isinstance(header, dict) or header.get("v") != 1:
        raise SessionError("no session header")
    if not _verify(verifier, header, block.get("header_signature")):
        raise SessionError("the session header is not signed by the monitor's key")
    if header.get("monitor_key_id") != verifier.key_id():
        raise SessionError("the session header names another monitor key")
    if workdir is not None and header.get("workdir") != os.path.realpath(workdir):
        raise SessionError(f"the session is for {header.get('workdir')!r}, not {os.path.realpath(workdir)!r}")
    if policy_hash is not None and header.get("policy_hash") != policy_hash:
        raise SessionError("the session header names another policy")
    session = header.get("session")
    start = block.get("from_checkpoint")
    if start is None: index, head = -1, GENESIS
    elif _checkpoint_ok(verifier, start, session): index, head = start["index"], start["head"]
    else: raise SessionError("the run's starting checkpoint is not the monitor's")
    records = block.get("records")
    if not isinstance(records, list): raise SessionError("no records")
    for r in records:
        if not isinstance(r, dict) or r.get("session") != session:
            raise SessionError("a record from another session")
        if r.get("index") != index + 1 or r.get("prev") != head:
            raise SessionError(f"the record chain is broken at {r.get('index')!r}")
        index, head = r["index"], sha(r)
    end = block.get("checkpoint")
    if not _checkpoint_ok(verifier, end, session) or (end["index"], end["head"]) != (index, head):
        raise SessionError("the run's checkpoint does not sign the head of its records")
    if calls is not None:
        if len(calls) != len(records):
            raise SessionError(f"{len(calls)} call(s) in the run, {len(records)} record(s) in the chain")
        for i, ((tool, kwargs, result), r) in enumerate(zip(calls, records)):
            if (r.get("op"), r.get("args_sha256"), r.get("result_sha256")) != (tool, sha(kwargs), result_sha(result)):
                raise SessionError(f"call {i} is not the call the monitor recorded")
    return header

def check_witnesses(header, calls):
    """Raise SessionError unless every file call's witness is from the header's
    root, and names a file beneath the header's workdir (F3)."""
    root, prefix = list(header.get("root") or []), header.get("workdir", "").rstrip("/") + "/"
    for i, (tool, _, result) in enumerate(calls):
        if tool not in ("file_read", "file_write") or not isinstance(result, dict): continue
        w = result.get("capability_witness")
        if not isinstance(w, dict): continue
        if [w.get("root_dev"), w.get("root_ino")] != root:
            raise SessionError(f"call {i}: its witness is from another root than the session's")
        if not str(w.get("fd_realpath", "")).startswith(prefix):
            raise SessionError(f"call {i}: its witness names a file outside the session's workdir")

def check_evidence(evidence, verifier, workdir=None, policy_hash=None):
    """Both checks, on a run record (critic_loop.evidence_of). Returns the header."""
    calls = [tuple(c) for c in evidence.get("calls", [])]
    header = check_block(evidence.get("session"), verifier, workdir, calls, policy_hash)
    check_witnesses(header, calls)
    return header


# --- the monitor as its own process (P0) -------------------------------------
#
# The gate starts it (RemoteMonitor) on one end of an AF_UNIX socketpair that
# it inherits. Before anything else it makes itself undumpable, so a process
# of the same user, its parent included, can neither ptrace it nor read its
# memory, and asks to die with its parent. It refuses a peer that is not that
# parent, generates its key (ML-DSA-65, or it refuses to start: a shared-secret
# key would have to be shared with the gate), signs the session header and
# sends it with its public key, then serves requests until the gate hangs up.
#
# Frames are length-prefixed on a SOCK_STREAM socketpair: a 4-byte big-endian
# length, then one canonical JSON object. (SOCK_SEQPACKET caps a message at the
# socket's send buffer, 212992 bytes by default, and a jailed run's raw trace
# can be longer.) A request is {"v": 1, "seq": n, "op": OP, "args": {...}},
# seq counting from 0, at most MAX_REQUEST bytes, with exactly OP's arguments,
# all strings. Anything else is a protocol violation: the monitor closes the
# connection and exits (PROTOCOL_EXIT), and the gate refuses every call after.
import signal, socket, struct, subprocess, sys

MAX_REQUEST = 1 << 20
MAX_RESPONSE = 256 << 20
PROTOCOL_EXIT = 3
# A space is where a call runs: "real", the workdir itself, whose every call
# is recorded in the session chain; or a copy, made by open_space from the
# real workdir or from another copy (clone_confined_snapshot) and mounted at
# the workdir's own path, for the critic's rehearsals and the co-signer's
# snapshots and replays. A copy's calls are not recorded: they change nothing
# real. An unknown space is a protocol violation, as an unknown op is.
OPS = {"file_read": ("space", "path"), "file_write": ("space", "path", "content"), "shell": ("space", "cmd"),
       "http_get": ("space", "url"), "checkpoint": (), "open_space": ("source", "kind"),
       "close_space": ("space",), "jail_status": (), "quarantine": ("layer", "reason", "call", "context")}
# What a copy is for; its directory is named after it, as the gate's own copies were.
KINDS = ("rehearsal", "snapshot", "replay")
MAX_SPACES = 64

class SpaceError(RuntimeError):
    """The monitor could not make a copy of the workdir."""

class MonitorGone(RuntimeError):
    """The monitor process is not there to answer: nothing more runs."""

def send_frame(sock, obj):
    data = canon(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 1 << 20))
        if not chunk: return None
        buf += chunk
    return bytes(buf)

def recv_frame(sock, limit):
    """The next frame's bytes; None at a clean end of stream. Raises
    ValueError for a frame over `limit` or a stream cut inside a frame."""
    head = _recv_exact(sock, 4)
    if head is None: return None
    (n,) = struct.unpack(">I", head)
    if n > limit: raise ValueError(f"a {n}-byte frame, over the {limit}-byte limit")
    data = _recv_exact(sock, n)
    if data is None: raise ValueError("the stream ended inside a frame")
    return data

def check_request(data, seq):
    """The request in `data`, if it is the next one and well formed; else ValueError."""
    try: obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError): raise ValueError("not JSON") from None
    if not isinstance(obj, dict) or canon(obj).encode() != data: raise ValueError("not canonical JSON")
    if set(obj) != {"v", "seq", "op", "args"} or obj["v"] != 1: raise ValueError("not a v1 request")
    if type(obj["seq"]) is not int or obj["seq"] != seq: raise ValueError(f"out of sequence (expected {seq})")
    args = obj["args"]
    if obj["op"] not in OPS or not isinstance(args, dict) or set(args) != set(OPS[obj["op"]]) \
            or not all(isinstance(v, str) for v in args.values()):
        raise ValueError(f"not a call to a known operation: {obj['op']!r}")
    return obj

def _harden():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_PDEATHSIG, PR_SET_DUMPABLE = 1, 4
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 or libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl")

def _reportable(args):
    """A refusal the gate may report: a layer it decides, a short reason, and
    a context hash or none."""
    ctx = args["context"]
    return args["layer"] in REPORTED and 0 < len(args["reason"]) <= Q_REASON and \
        (ctx == "" or (len(ctx) == 64 and all(c in "0123456789abcdef" for c in ctx)))

def serve(fd, workdir, policy_hash, vow_hash, quarantine=""):
    _harden()
    parent = os.getppid()
    sock = socket.socket(fileno=fd)
    pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    if (pid, uid) != (parent, os.getuid()) or parent == 1:
        print(f"monitor: refusing peer pid {pid} uid {uid}", file=sys.stderr); return 1
    from signing import MLDSASigner
    from tools import Sandbox, dispatch
    try: signer = MLDSASigner.generate("Monitor")
    except ImportError:
        send_frame(sock, {"v": 1, "refused": "no ML-DSA-65 (pip install dilithium-py)"}); return 1
    import shutil, tempfile
    from cw_vfs import ConfinementViolation, clone_confined_snapshot
    try: mon = Monitor(signer, workdir, policy_hash=policy_hash, vow_hash=vow_hash, quarantine=quarantine or None)
    except (ValueError, OSError) as e:
        send_frame(sock, {"v": 1, "refused": str(e)}); return 1
    real = mon.header["workdir"]
    spaces = {"real": (None, Sandbox(real, jail=True, monitor=mon, parse_trace=False))}
    made = 0
    send_frame(sock, {"v": 1, "hello": {"header": mon.header, "header_signature": mon.header_signature,
                                         "scheme": signer.scheme, "public": signer.public_bytes().hex()}})
    seq = 0
    try:
        while True:
            try:
                data = recv_frame(sock, MAX_REQUEST)
                if data is None: return 0                       # the gate hung up
                req = check_request(data, seq)
                op, args = req["op"], req["args"]
                named = args.get("space", args.get("source"))
                if named is not None and named not in spaces: raise ValueError(f"no space {named!r}")
                if op == "close_space" and named == "real": raise ValueError("the real space is not closed")
                if op == "open_space" and args["kind"] not in KINDS: raise ValueError(f"no kind {args['kind']!r}")
                if op == "quarantine" and not _reportable(args): raise ValueError("not a refusal the gate may report")
            except ValueError as e:
                print(f"monitor: protocol violation: {e}", file=sys.stderr); return PROTOCOL_EXIT
            reply = {"v": 1, "seq": seq, "ok": True}
            if op == "checkpoint":
                reply["block"] = mon.end_run()
            elif op == "jail_status":
                import jail
                reply["jail"], reply["why"] = jail.available()
            elif op == "open_space":
                if len(spaces) > MAX_SPACES:
                    reply.update(space=None, error=f"more than {MAX_SPACES} spaces open")
                else:
                    root = tempfile.mkdtemp(prefix=args["kind"] + "_"); copy = os.path.join(root, "w")
                    try:
                        clone_confined_snapshot(spaces[named][1].workdir, copy)
                        made += 1; sid = f"copy{made}"
                        spaces[sid] = (root, Sandbox(copy, jail=True, logical_workdir=real, parse_trace=False))
                        reply["space"] = sid
                    except ConfinementViolation as e:
                        shutil.rmtree(root, ignore_errors=True)
                        reply.update(space=None, error=f"the workdir cannot be copied: {e}")
            elif op == "close_space":
                root, sb = spaces.pop(named); sb.close(); shutil.rmtree(root, ignore_errors=True)
            elif op == "quarantine":
                rec, cp = mon.report_refusal(args["layer"], args["reason"], args["call"], args["context"])
                reply["quarantine"] = {"record": rec, "checkpoint": cp}
            else:
                sb = spaces[named][1]
                kwargs = {k: v for k, v in args.items() if k != "space"}
                mon.quarantined = None
                reply["result"] = dispatch(sb, op, kwargs)       # the fixed tool table (F4)
                reply["record"] = mon.records[-1] if named == "real" else None
                if mon.quarantined is not None:                  # a call it ran and refused
                    reply["quarantine"] = dict(zip(("record", "checkpoint"), mon.quarantined))
                sb.calls.clear()
            send_frame(sock, reply)
            seq += 1
    finally:
        for root, sb in spaces.values():
            sb.close()
            if root: shutil.rmtree(root, ignore_errors=True)
        sock.close()

def start(workdir, policy_hash="", vow_hash="", quarantine=None):
    """The session's monitor: its own process when ML-DSA-65 is installed
    (RemoteMonitor), else a Monitor in this process under an HMAC key, which
    doctor reports as DEGRADED like every shared-secret signer."""
    try:
        import dilithium_py.ml_dsa  # noqa: F401
    except ImportError:
        from signing import default_signer
        return Monitor(default_signer("Monitor"), workdir, policy_hash=policy_hash, vow_hash=vow_hash,
                       quarantine=quarantine)
    return RemoteMonitor(workdir, policy_hash=policy_hash, vow_hash=vow_hash, quarantine=quarantine)

class RemoteMonitor:
    """The gate's handle on a monitor process for `workdir`. It holds the
    monitor's public key, never its signing key."""
    def __init__(self, workdir, policy_hash="", vow_hash="", timeout=60, quarantine=None):
        from signing import PublicVerifier
        self.workdir = os.path.realpath(workdir)
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        here = os.path.dirname(os.path.abspath(__file__))
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-E", "-s", os.path.join(here, "monitor.py"), "serve",
                 str(theirs.fileno()), self.workdir, policy_hash, vow_hash, quarantine or ""],
                pass_fds=[theirs.fileno()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, cwd=here)
        finally:
            theirs.close()
        self._sock, self._seq, self.last_block = ours, 0, None
        # The monitor's quarantine stream as it answers: each record it made,
        # and the checkpoint it signed over the last one.
        self.quarantine_records, self.quarantine_checkpoint = [], None
        self._sock.settimeout(timeout)
        hello = self._recv()
        if "hello" not in hello:
            self.close(); raise MonitorGone(f"the monitor refused to start: {hello.get('refused', hello)}")
        h = hello["hello"]
        self.header, self.header_signature = h["header"], h["header_signature"]
        self.verifier = PublicVerifier("Monitor", h["scheme"], bytes.fromhex(h["public"]))
        if not _verify(self.verifier, self.header, self.header_signature) or \
                self.header.get("workdir") != self.workdir:
            self.close(); raise MonitorGone("the monitor's session header does not check")
    @property
    def pid(self): return self._proc.pid
    @property
    def session(self): return self.header["session"]

    def _recv(self):
        try: data = recv_frame(self._sock, MAX_RESPONSE)
        except (OSError, ValueError) as e: raise MonitorGone(f"the monitor stopped answering: {e}") from None
        if data is None: raise MonitorGone("the monitor process is gone")
        return json.loads(data)

    def call(self, op, **args):
        try: send_frame(self._sock, {"v": 1, "seq": self._seq, "op": op, "args": args})
        except OSError as e: raise MonitorGone(f"the monitor process is gone: {e}") from None
        resp = self._recv()
        if resp.get("seq") != self._seq or not resp.get("ok"):
            raise MonitorGone(f"the monitor answered out of turn: {str(resp)[:120]}")
        self._seq += 1
        q = resp.get("quarantine")
        if q is not None:
            if q.get("record") is not None: self.quarantine_records.append(q["record"])
            self.quarantine_checkpoint = q.get("checkpoint")
        return resp

    def report_refusal(self, layer, reason, call, context=""):
        """A refusal the gate decided (a Vow or guard refusal), into the monitor's stream."""
        r = self.call("quarantine", layer=layer, reason=reason, call=call, context=context)["quarantine"]
        return r["record"], r["checkpoint"]

    def begin_run(self): pass
    def end_run(self):
        self.last_block = self.call("checkpoint")["block"]
        return self.last_block
    def sandbox(self, workdir, jail=False, logical_workdir=None):
        if os.path.realpath(workdir) != self.workdir or \
                (logical_workdir is not None and os.path.realpath(logical_workdir) != self.workdir):
            raise ValueError(f"this monitor serves {self.workdir}, not {workdir}")
        return RemoteSandbox(self, "real")

    def open_space(self, source="real", kind="rehearsal"):
        """A new copy of `source` (the real workdir, or a copy), mounted at the
        workdir's path when commands run in it. Raises SpaceError if it cannot be made."""
        r = self.call("open_space", source=source, kind=kind)
        if r.get("space") is None: raise SpaceError(r.get("error", "no space"))
        return r["space"]
    def close_space(self, space): self.call("close_space", space=space)
    def space_sandbox(self, space): return RemoteSandbox(self, space)
    def jail_status(self):
        r = self.call("jail_status")
        return bool(r["jail"]), r["why"]

    def close(self):
        try: self._sock.close()
        except OSError: pass
        try: self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired: self._proc.kill(); self._proc.wait()
    def __del__(self):
        try: self.close()
        except Exception: pass

class RemoteSandbox:
    """A Sandbox whose calls the monitor process runs and records. The gate
    reads a shell call's raw trace itself (jail.parse)."""
    dry_run = False
    def __init__(self, mon, space="real"):
        import pathlib
        self._mon, self.space = mon, space
        self.workdir = self.logical_workdir = pathlib.Path(mon.workdir)
        self.calls = []
    def _call(self, tool, **kwargs):
        result = self._mon.call(tool, space=self.space, **kwargs)["result"]
        if tool == "shell" and result.get("jailed"):
            import jail
            # None when the trace never shows the command starting: no events,
            # and the co-signer's own reading (witness.events_for) refuses it.
            result["events"] = jail.parse({int(p): t for p, t in result["trace"].items()}, kwargs["cmd"]) or []
        self.calls.append((tool, kwargs, result))
        return result
    def file_read(self, path): return self._call("file_read", path=str(path))
    def file_write(self, path, content): return self._call("file_write", path=str(path), content=content)
    def shell(self, cmd): return self._call("shell", cmd=cmd)
    def http_get(self, url): return self._call("http_get", url=url)
    def close(self): pass

if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "serve":
        sys.exit(serve(int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]))
    print("usage: monitor.py serve FD WORKDIR POLICY_HASH VOW_HASH QUARANTINE (started by RemoteMonitor)",
          file=sys.stderr)
    sys.exit(2)
