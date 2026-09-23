
import pathlib

class Sandbox:
    def __init__(self, workdir, dry_run=False):
        self.workdir = pathlib.Path(workdir); self.dry_run = dry_run
        if not dry_run: self.workdir.mkdir(parents=True, exist_ok=True)
        self.calls = []
    def _record(self, tool, kwargs, result):
        self.calls.append((tool, kwargs, result))
    def file_read(self, path):
        kwargs = {"path": str(path)}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            p = pathlib.Path(path)
            if not p.is_absolute(): p = self.workdir / p
            try: content = p.read_text()[:2000]; r = {"ok": True, "bytes": len(content)}
            except Exception as e: r = {"ok": False, "error": str(e)}
        self._record("file_read", kwargs, r); return r
    def file_write(self, path, content):
        kwargs = {"path": str(path), "content": content}
        if self.dry_run: r = {"ok": True, "dry_run": True}
        else:
            p = pathlib.Path(path)
            if not p.is_absolute(): p = self.workdir / p
            try:
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
        r = {"ok": True, "cmd": cmd, "blocked": True}
        self._record("shell", kwargs, r); return r
