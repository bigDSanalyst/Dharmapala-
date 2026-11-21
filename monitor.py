# The monitor's record of a session: what P0 signs (docs/monitor-boundary.md, section 5).
#
# A capability witness proves that a file call was confined beneath some root,
# but not which one: a well-formed witness from any directory verified (F3).
# The monitor is what holds the workdir, so it states the root once, in a
# session header it signs, and records every real call in a hash chain whose
# head it signs at the end of each run. A co-signer, and verify.py later,
# check a run's witnesses against the header and its calls against the chain.
#
# This runs in the gate's own process for now (Phase 2, slice 1): the format
# and the checks come first, so the process split (slice 2) moves code without
# changing what is signed. Until then a fault in the gate's process can sign
# anything the monitor can.
#
#   header      {v, session, workdir, root: [dev, ino], resolve_mask,
#                policy_hash, vow_hash, monitor_code_hash, monitor_key_id, start}
#   record i    {index, prev, session, op, args_sha256, result_sha256, time}
#   checkpoint  {session, index, head}: the last record's index and hash
#
# Each is canonical JSON (sorted keys, no spaces), and each signature is over
# that encoding. A run's evidence carries a "session" block: the signed header,
# the checkpoint the run started from (None for the first), the run's records
# and the checkpoint it ended on.
import hashlib, json, os, secrets, stat, time

GENESIS = "0" * 64
CODE = ("monitor.py", "tools.py", "cw_vfs.py", "jail.py", "confine.py")

def canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))
def sha(obj): return hashlib.sha256(canon(obj).encode()).hexdigest()

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

class Monitor:
    def __init__(self, signer, workdir, policy_hash="", vow_hash="", resolve_mask=None):
        from signing import verifier_for
        import cw_vfs
        path, dev, ino = root_of(workdir)
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
        self._run_from = 0
        self.last_block = None            # the session block of the last run
    @property
    def session(self): return self.header["session"]
    def head(self): return sha(self.records[-1]) if self.records else GENESIS
    def _sign(self, obj): return self._signer.sign(canon(obj).encode()).hex()

    def record(self, op, kwargs, result):
        r = {"index": len(self.records), "prev": self.head(), "session": self.session, "op": op,
             "args_sha256": sha(kwargs), "result_sha256": sha(result),
             "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.records.append(r)
        return r

    def begin_run(self): self._run_from = len(self.records)

    def end_run(self):
        """Sign a checkpoint over the head and return the run's session block."""
        before = self._checkpoint
        cp = {"session": self.session, "index": len(self.records) - 1, "head": self.head()}
        self._checkpoint = dict(cp, signature=self._sign(cp))
        self.last_block = {"header": self.header, "header_signature": self.header_signature,
                           "from_checkpoint": before, "records": self.records[self._run_from:],
                           "checkpoint": self._checkpoint}
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
            if (r.get("op"), r.get("args_sha256"), r.get("result_sha256")) != (tool, sha(kwargs), sha(result)):
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
