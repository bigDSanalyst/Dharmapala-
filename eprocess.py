
import math
from dataclasses import dataclass

@dataclass
class EProcessResult:
    n: int; refusal_rate: float; log_e: float
    threshold: float; drifted: bool; direction: str

class EProcessDrift:
    def __init__(self, p0=0.15, c=0.5, alpha=0.01):
        self.p0 = p0; self.c = c
        self.threshold = math.log(1.0 / alpha)
        self.log_e = 0.0; self.S = 0.0; self.t = 0; self.refusals = 0
    def update(self, is_refusal):
        x = 1.0 if is_refusal else 0.0
        lam = self.S / (self.t + 1.0)
        lam = max(-self.c, min(self.c, lam))
        self.log_e += math.log(1.0 + lam * (x - self.p0))
        self.S += (x - self.p0); self.t += 1
        self.refusals += int(x)
        return self.log_e > self.threshold
    def report(self):
        return EProcessResult(n=self.t,
                              refusal_rate=self.refusals / max(self.t, 1),
                              log_e=self.log_e, threshold=self.threshold,
                              drifted=self.log_e > self.threshold,
                              direction="rising" if self.S > 0 else "falling")

def outcomes(ledger):
    # One observation per engagement, in the order they happened: every audit
    # entry is a refusal, and a record counts as one when its verdict is
    # LEARNING. An audit written at epoch k precedes the record appended at k.
    # Engagements erased by compression come first, as the checkpoint carried
    # them: a drift monitor that restarted at every checkpoint would get a
    # fresh chance to cross its threshold each time.
    carried = [c == "1" for c in ledger.carried()["outcomes"]] if hasattr(ledger, "carried") else []
    ev = [(a.epoch, 0, i, True) for i, a in enumerate(ledger.audits)]
    ev += [(r.index, 1, i, r.verdict_kind == "LEARNING") for i, r in enumerate(ledger.records)]
    return carried + [refused for *_, refused in sorted(ev)]

def analyze(ledger, p0=0.15, alpha=0.01):
    ep = EProcessDrift(p0=p0, alpha=alpha)
    for refused in outcomes(ledger):
        ep.update(refused)
    return ep.report()

def render(r):
    flag = "DRIFT" if r.drifted else "ok"
    return (f"  {flag}  refusals={r.refusal_rate:.1%} over {r.n} "
            f"(log e = {r.log_e:.2f} vs threshold {r.threshold:.2f})")
