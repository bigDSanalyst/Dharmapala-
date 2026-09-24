
import os, pathlib, shutil, subprocess, tempfile

if shutil.which('lean') is None:
    elan = pathlib.Path.home() / '.elan' / 'bin'
    if (elan / 'lean').exists():
        os.environ['PATH'] = f"{elan}:" + os.environ.get('PATH', '')

def _probe(path):
    # Finding a file named lean is not the same as being able to run it: an
    # elan shim with no toolchain downloaded is found on PATH and then fails.
    if path is None: return None, "no lean on PATH"
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"lean at {path} does not run: {e}"
    if r.returncode != 0:
        out = [l for l in (r.stderr or r.stdout or "").splitlines() if l.strip()]
        why = next((l for l in out if l.startswith("error")), out[-1] if out else f"exit {r.returncode}")
        return None, f"lean at {path} does not run: {why.strip()}"
    return path, r.stdout.strip()

_LEAN, _LEAN_STATUS = _probe(shutil.which('lean'))

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
    except OSError as e:
        return False, f"lean found at {_LEAN} but could not run: {e}"
    finally:
        try: os.remove(path)
        except FileNotFoundError: pass

def which_critic():
    return "lean" if _LEAN else "python-degraded"

def critic_status():
    return _LEAN_STATUS
