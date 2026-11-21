
import pathlib
from cw_vfs import CapabilityDirJail

class Sandbox:
    def __init__(self, workdir, dry_run=False, jail=False, logical_workdir=None):
        # jail=True: shell commands really run, inside jail.py's jail, traced.
        # Otherwise they are recorded and never run, as before. Either way a
        # dry run runs nothing.
        self.workdir = pathlib.Path(workdir); self.dry_run = dry_run; self.jail = jail
        # logical_workdir: the workdir this sandbox stands in for (a rehearsal
        # runs in a copy). Paths are judged, and shown to commands, as there.
        self.logical_workdir = (pathlib.Path(logical_workdir) if logical_workdir is not None
                                else self.workdir)
        self._vfs = None
        if not dry_run:
            self.workdir.mkdir(parents=True, exist_ok=True)
            self._vfs = CapabilityDirJail(self.workdir, logical_workdir=logical_workdir)
        self.calls = []

    def close(self):
        if self._vfs is not None:
            self._vfs.close()
    def _record(self, tool, kwargs, result):
        self.calls.append((tool, kwargs, result))
    def file_read(self, path):
        kwargs = {"path": str(path)}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            try:
                data, truncated, wit = self._vfs.read_bytes(str(path), max_bytes=2000)
                try: content = data.decode("utf-8")
                except UnicodeDecodeError as e:
                    # The 2000-byte cut fell inside a character: read up to its
                    # start instead, so the witness covers exactly what is returned.
                    if not truncated or e.start < len(data) - 3: raise
                    data, truncated, wit = self._vfs.read_bytes(str(path), max_bytes=e.start)
                    content = data.decode("utf-8")
                r = {"ok": True, "bytes": len(content), "content": content,
                     "truncated": truncated,
                     "content_sha256": wit.content_sha256,
                     "capability_witness": wit.to_dict()}
            except Exception as e: r = {"ok": False, "error": str(e)}
        self._record("file_read", kwargs, r); return r
    def file_write(self, path, content):
        kwargs = {"path": str(path), "content": content}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            try:
                raw = content.encode("utf-8")
                wit = self._vfs.write_bytes_atomic(str(path), raw)
                r = {"ok": True, "bytes": len(content),
                     "content_sha256": wit.content_sha256,
                     "capability_witness": wit.to_dict()}
            except Exception as e: r = {"ok": False, "error": str(e)}
        self._record("file_write", kwargs, r); return r
    def http_get(self, url):
        kwargs = {"url": url}
        r = {"ok": True, "url": url, "sandbox": True}
        self._record("http_get", kwargs, r); return r
    def shell(self, cmd):
        kwargs = {"cmd": cmd}
        if self.jail and not self.dry_run:
            import jail
            try:
                # The copy is mounted at the logical workdir's path, so the
                # command sees, and the trace records, the paths the evidence names.
                same = self.logical_workdir == self.workdir
                ex = jail.run(cmd, str(self.logical_workdir), source=None if same else str(self.workdir))
                r = {"ok": ex.returncode == 0 and not ex.timed_out, "cmd": cmd, "jailed": True,
                     "returncode": ex.returncode, "stdout": ex.stdout[:2000],
                     "timed_out": ex.timed_out, "events": ex.events,
                     # the raw trace, so a co-signer can read it with its own parser (witness.py)
                     "trace": {str(pid): text for pid, text in ex.trace.items()}}
            except jail.JailUnavailable as e:
                r = {"ok": False, "cmd": cmd, "jailed": False, "error": f"not run: {e}"}
        else:
            r = {"ok": True, "cmd": cmd, "blocked": True}
        self._record("shell", kwargs, r); return r


# How a plan's calls reach a Sandbox: a fixed table of the four tools and
# exactly their arguments, never getattr on a name the plan supplies. That
# would run any attribute: a plan naming __init__ re-roots the sandbox
# (docs/monitor-boundary.md, F4). guarded_agent.ARGS is the same table, as
# the model sees it (tests/test_dispatch.py keeps the two in step).
TOOL_ARGS = {"file_read": ("path",), "file_write": ("path", "content"),
             "shell": ("cmd",), "http_get": ("url",)}
_DISPATCH = {"file_read": Sandbox.file_read, "file_write": Sandbox.file_write,
             "shell": Sandbox.shell, "http_get": Sandbox.http_get}

class UnknownCall(ValueError):
    """A plan step that is not a call to one of the four tools with exactly its arguments."""

def check_call(tool, kwargs):
    """Refuse (UnknownCall) anything but one of the four tools with exactly
    its own arguments, every one a string."""
    if not isinstance(tool, str) or tool not in _DISPATCH or not isinstance(kwargs, dict) \
            or set(kwargs) != set(TOOL_ARGS[tool]) or not all(isinstance(v, str) for v in kwargs.values()):
        raise UnknownCall(f"not a call to a known tool: {tool!r}")

def dispatch(sandbox, tool, kwargs):
    """Run one call on `sandbox` through the table."""
    check_call(tool, kwargs)
    return _DISPATCH[tool](sandbox, **kwargs)
