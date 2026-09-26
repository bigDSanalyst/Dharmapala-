
import pathlib

class Sandbox:
    def __init__(self, workdir, dry_run=False, jail=False):
        # jail=True: shell commands really run, inside jail.py's jail, traced.
        # Otherwise they are recorded and never run, as before. Either way a
        # dry run runs nothing.
        self.workdir = pathlib.Path(workdir); self.dry_run = dry_run; self.jail = jail
        if not dry_run: self.workdir.mkdir(parents=True, exist_ok=True)
        self.calls = []
    def _record(self, tool, kwargs, result):
        self.calls.append((tool, kwargs, result))
    def _resolve(self, path):
        # An absolute path says where it goes, and observation.py judges it.
        # A relative path means "in the workdir": one that resolves anywhere
        # else (../, or a symlink inside the workdir) is refused, not followed.
        p = pathlib.Path(path)
        if p.is_absolute(): return p
        q = (self.workdir / p).resolve()
        if not q.is_relative_to(self.workdir.resolve()):
            raise PermissionError(f"{path!r} resolves outside the workdir")
        return q
    def file_read(self, path):
        kwargs = {"path": str(path)}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            try: content = self._resolve(path).read_text()[:2000]; r = {"ok": True, "bytes": len(content)}
            except Exception as e: r = {"ok": False, "error": str(e)}
        self._record("file_read", kwargs, r); return r
    def file_write(self, path, content):
        kwargs = {"path": str(path), "content": content}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            try:
                p = self._resolve(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content); r = {"ok": True, "bytes": len(content)}
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
                ex = jail.run(cmd, str(self.workdir))
                r = {"ok": ex.returncode == 0 and not ex.timed_out, "cmd": cmd, "jailed": True,
                     "returncode": ex.returncode, "stdout": ex.stdout[:2000],
                     "timed_out": ex.timed_out, "events": ex.events}
            except jail.JailUnavailable as e:
                r = {"ok": False, "cmd": cmd, "jailed": False, "error": f"not run: {e}"}
        else:
            r = {"ok": True, "cmd": cmd, "blocked": True}
        self._record("shell", kwargs, r); return r
