
import os, pathlib, shutil, subprocess, tempfile

if shutil.which('lean') is None:
    elan = pathlib.Path.home() / '.elan' / 'bin'
    if (elan / 'lean').exists():
        os.environ['PATH'] = f"{elan}:" + os.environ.get('PATH', '')
_LEAN = shutil.which('lean')

def _python_decide(source):
    effects = []
    for line in source.splitlines():
        s = line.strip()
        if s.startswith("def proposedEffects"):
            body = s.split(":=", 1)[1].strip().strip("[]").replace("Effect.", "")
            effects = [e.strip() for e in body.split(",") if e.strip()]
            break
    failures = []
    for line in source.splitlines():
        s = line.strip()
        if s.startswith("example : Effect.") and "\u2209 proposedEffects" in s:
            effect = s.split("Effect.", 1)[1].split(" ", 1)[0].rstrip(".")
            if effect in effects: failures.append(effect)
    if failures: return False, f"python-degraded: {failures} present"
    return True, "python-degraded: all forbidden effects absent"

def check(lean_source, lake_root=None, timeout=15.0):
    if _LEAN is None:
        ok, msg = _python_decide(lean_source)
        return ok, f"[no Lean toolchain] {msg}"
    fd, path = tempfile.mkstemp(suffix='.lean', prefix='critic_')
    os.close(fd)
    try:
        with open(path, 'w') as f: f.write(lean_source)
        r = subprocess.run([_LEAN, path], capture_output=True, text=True, timeout=timeout)
        combined = (r.stdout or "") + (r.stderr or "")
        return r.returncode == 0, combined.strip() or "lean accepted"
    except subprocess.TimeoutExpired:
        return False, f"lean timed out after {timeout}s"
    finally:
        try: os.remove(path)
        except FileNotFoundError: pass

def which_critic():
    return "lean" if _LEAN else "python-degraded"
