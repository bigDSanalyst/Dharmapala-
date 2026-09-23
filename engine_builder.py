
import ctypes, hashlib, os, subprocess

C_SOURCE = r"""
#include <stdint.h>
void zq3329_butterflies(const uint16_t *a, const uint16_t *b,
                        const uint16_t *w,
                        uint16_t *ea, uint16_t *eb, int n) {
    const uint32_t q = 3329;
    for (int i = 0; i < n; i++) {
        uint32_t wi = (uint32_t)w[i];
        uint32_t bi = (uint32_t)b[i];
        ea[i] = (uint16_t)(((uint32_t)a[i] + wi * bi) % q);
        eb[i] = (uint16_t)(((uint32_t)a[i] + (q - wi) * bi) % q);
    }
}
"""

def build_engine(workdir):
    c_path = os.path.join(workdir, "libzq_demo.c")
    so_path = os.path.join(workdir, "libzq_demo.so")
    with open(c_path, "w") as f: f.write(C_SOURCE)
    proc = subprocess.run(["gcc", "-O3", "-shared", "-fPIC",
                           "-o", so_path, c_path, "-lm"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"engine compile failed:\n{proc.stderr}")
    binary_hash = hashlib.sha256(open(so_path, "rb").read()).hexdigest()
    lib = ctypes.CDLL(so_path)
    lib.zq3329_butterflies.argtypes = [
        ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16), ctypes.c_int]
    lib.zq3329_butterflies.restype = None
    def run_fn(inputs):
        triples = inputs["butterflies"]
        n = len(triples)
        a_arr = (ctypes.c_uint16 * n)(*[t[0] for t in triples])
        b_arr = (ctypes.c_uint16 * n)(*[t[1] for t in triples])
        w_arr = (ctypes.c_uint16 * n)(*[t[2] for t in triples])
        ea_arr = (ctypes.c_uint16 * n)()
        eb_arr = (ctypes.c_uint16 * n)()
        lib.zq3329_butterflies(a_arr, b_arr, w_arr, ea_arr, eb_arr, n)
        return {"butterflies": [
            {"a": a_arr[i], "b": b_arr[i], "w": w_arr[i],
             "ea": ea_arr[i], "eb": eb_arr[i]} for i in range(n)]}
    return so_path, binary_hash, run_fn
