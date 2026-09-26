import shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

import lake_critic  # noqa: E402

# The layer each toolchain provides, as run_demo.py names it.
LAYER = {"lean": "lean critic", "coqc": "coq certificates",
         "dilithium-py": "ml-dsa-65 signatures", "jail": "jail (real execution, traced)"}

def toolchain_missing():
    missing = []
    if lake_critic.which_critic() != "lean": missing.append("lean")
    if shutil.which("coqc") is None: missing.append("coqc")
    try: import dilithium_py.ml_dsa  # noqa: F401
    except ImportError: missing.append("dilithium-py")
    import jail
    if not jail.available()[0]: missing.append("jail")
    return missing
