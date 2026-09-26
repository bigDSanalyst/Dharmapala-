
import hashlib, json, os, shutil, subprocess, tempfile
from dataclasses import dataclass, replace

@dataclass(frozen=True)
class CoqWitness:
    name: str; statement: str; engine_output: dict; engine_name: str
    def __post_init__(self):
        s = self.statement.strip()
        if s.startswith("(*") or s.startswith("//"):
            raise ValueError(f"witness {self.name!r}: statement is a comment")

COQC_TIMEOUT = 60.0

class Certificate:
    def __init__(self, label):
        self.label = label; self.witnesses = []; self.preamble = []
    def add(self, w): self.witnesses.append(w); return self
    def define(self, lines): self.preamble.extend(lines); return self
    def emit(self, path=None):
        if path is None:
            fd, path = tempfile.mkstemp(suffix=".v", prefix=f"pqv_{self.label}_")
            os.close(fd)
        lines = [f"(* CERTIFICATE: {self.label} *)",
                 "Require Import ZArith.", "Open Scope Z_scope.", ""]
        lines += self.preamble + ([""] if self.preamble else [])
        for w in self.witnesses:
            lines.append(f"Theorem {w.name} : {w.statement}.")
            lines.append("Proof. vm_compute. reflexivity. Qed.")
            lines.append("")
        with open(path, "w") as f: f.write("\n".join(lines))
        return path
    @staticmethod
    def check(path, timeout=None):
        # True: coqc accepted it. False: coqc ran and rejected it.
        # None: nothing was checked - coqc is missing, will not run, or hung.
        # A hang is not a rejection: reading it as one would refuse a correct
        # certificate and record the machine's slowness as the agent's refusal.
        timeout = COQC_TIMEOUT if timeout is None else timeout
        coqc = shutil.which("coqc")
        if coqc is None: return None, "coqc not in PATH"
        try:
            # Run the coqc that was found, not the name: if that one will not
            # execute, exec would quietly go on to the next coqc on PATH.
            proc = subprocess.run([coqc, path], capture_output=True,
                                  text=True, timeout=timeout)
            for ext in (".vo", ".glob", ".vok", ".vos"):
                try: os.remove(path.replace(".v", ext))
                except FileNotFoundError: pass
            return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            return None, f"coqc timed out after {timeout}s: not checked"
        except OSError as e:
            return None, f"coqc found but could not run: {e}"
    def certificate_hash(self):
        # The preamble is hashed too: it defines what the statements mean.
        payload = "\n".join(self.preamble) + "||" + "|".join(
            f"{w.name}:{w.statement}" for w in self.witnesses)
        return hashlib.sha256(payload.encode()).hexdigest()

@dataclass(frozen=True)
class Attestation:
    engine_id: str; engine_name: str; binary_hash: str; epoch: int
    inputs_hash: str; certificate_hash: str; output_hash: str
    co_signer_id: str; certificate_status: str = ""
    # What was decided, and about which action under which Vow. Signed, so an
    # attestation cannot be moved to another record (ledger.verify_integrity).
    action_digest: str = ""; vow_hash: str = ""; verdict: str = ""
    evidence_digest: str = ""       # the run record the co-signer re-derived the effects from
    signature: str = ""
    @property
    def signer_id(self): return self.co_signer_id
    def payload(self):
        return (f"{self.engine_id}|{self.engine_name}|{self.binary_hash}|"
                f"{self.epoch}|{self.inputs_hash}|{self.certificate_hash}|"
                f"{self.output_hash}|{self.co_signer_id}|"
                f"{self.certificate_status}|{self.action_digest}|"
                f"{self.vow_hash}|{self.verdict}|{self.evidence_digest}").encode()
    def attestation_hash(self):
        return hashlib.sha256(self.payload()).hexdigest()

class RefusedToSign(Exception): pass
class ConfigError(Exception): pass
class DecisionError(Exception): pass

def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

def build_certificate(label, outputs, decision=None, q=3329):
    # One construction for proposer and co-signer alike, so the co-signer can
    # rebuild the certificate it is asked to vouch for instead of trusting it.
    cert = Certificate(label)
    for i, b in enumerate(outputs.get("butterflies", [])):
        we, wo = witness_zq_butterfly(q, b["a"], b["b"], b["w"], b["ea"], b["eb"], i)
        cert.add(we).add(wo)
    if decision is not None:
        cert.define(decision.coq_preamble())
        cert.add(CoqWitness(name="decision", statement=decision.coq_statement(),
                            engine_output={"verdict": decision.verdict},
                            engine_name="vow/decision"))
    return cert

def propose(engine_id, engine_name, binary_hash, epoch, inputs, cert, outputs,
            co_signer_id, decision=None):
    return Attestation(engine_id=engine_id, engine_name=engine_name,
                       binary_hash=binary_hash, epoch=epoch,
                       inputs_hash=_hash(inputs),
                       certificate_hash=cert.certificate_hash(),
                       output_hash=_hash(outputs), co_signer_id=co_signer_id,
                       action_digest=decision.action_digest if decision else "",
                       vow_hash=decision.vow_hash if decision else "",
                       verdict=decision.verdict if decision else "",
                       evidence_digest=decision.evidence_digest if decision else "")

class CoSigner:
    def __init__(self, signer, require_coqc=False):
        self.id = signer.id; self._signer = signer
        self.require_coqc = require_coqc; self.notes = []
    def cosign(self, proposal, cert_path, inputs, binary_path, re_run_fn, decision=None, evidence=None):
        self.notes = []
        if proposal.co_signer_id != self.id:
            raise RefusedToSign("proposal addressed to a different co-signer")
        actual_bin = hashlib.sha256(open(binary_path, "rb").read()).hexdigest()
        if actual_bin != proposal.binary_hash:
            self.notes.append("binary: MISMATCH")
            raise RefusedToSign(f"binary mismatch")
        self.notes.append("binary hash: match")
        if _hash(inputs) != proposal.inputs_hash:
            self.notes.append("inputs: MISMATCH")
            raise RefusedToSign("inputs hash mismatch")
        self.notes.append("inputs hash: match")
        recomputed = re_run_fn(inputs)
        if _hash(recomputed) != proposal.output_hash:
            self.notes.append("output: MISMATCH")
            raise RefusedToSign("output mismatch")
        self.notes.append("re-run output: match")
        if decision is not None:
            # Decide independently, then check the proposal says the same.
            from decision import verdict_of
            mine = verdict_of(decision.effects, decision.forbidden)
            if (mine, decision.action_digest, decision.vow_hash, decision.evidence_digest) != \
                    (proposal.verdict, proposal.action_digest, proposal.vow_hash, proposal.evidence_digest):
                self.notes.append("decision: MISMATCH")
                raise RefusedToSign(f"decision mismatch: proposal={proposal.verdict} cosigner={mine}")
            self.notes.append("decision: match")
            if decision.evidence_digest:
                # Observe for itself: re-derive the effects from the run record
                # rather than taking the guard's account of them.
                from critic_loop import effects_from_evidence, evidence_digest
                if evidence is None:
                    raise RefusedToSign("decision cites a run record the co-signer was not shown")
                if evidence_digest(evidence) != decision.evidence_digest:
                    self.notes.append("evidence: MISMATCH")
                    raise RefusedToSign("run record does not match the digest the decision cites")
                # Read the raw trace with the co-signer's own parser, not the
                # events the guard's side parsed from it (witness.py).
                import witness
                try: seen = tuple(sorted(effects_from_evidence(evidence, reread=witness.events_for)))
                except witness.Unreadable as e:
                    self.notes.append("trace: UNREADABLE")
                    raise RefusedToSign(f"co-signer cannot read the run's trace: {e}")
                if seen != decision.effects:
                    self.notes.append("effects: MISMATCH")
                    raise RefusedToSign(f"co-signer observed {list(seen)} where the guard reports {list(decision.effects)}")
                self.notes.append("effects: re-derived, match")
        elif proposal.verdict or proposal.action_digest:
            raise RefusedToSign("proposal carries a decision the co-signer was not shown")
        # Check the certificate this co-signer builds, not the file it was
        # handed: the handed file need not be the one whose hash was proposed.
        own = build_certificate(f"cosign_{self.id}", recomputed, decision)
        if own.certificate_hash() != proposal.certificate_hash:
            self.notes.append("certificate: MISMATCH")
            raise RefusedToSign("certificate hash mismatch")
        own_path = own.emit()
        try: ok, out = Certificate.check(own_path)
        finally:
            try: os.remove(own_path)
            except FileNotFoundError: pass
        if ok is None:
            self.notes.append("certificate: coqc unavailable")
            if self.require_coqc:
                raise ConfigError(f"certificate not checked: {out}")
            status = "coqc-unavailable"
        elif not ok:
            self.notes.append("certificate: coqc FAIL")
            raise RefusedToSign("certificate failed coqc")
        else:
            self.notes.append("certificate: coqc PASS")
            status = "coqc-pass"
        # The status is signed: an attestation says whether its certificate
        # was actually checked, and doctor can count the ones that were not.
        unsigned = replace(proposal, certificate_status=status)
        return replace(unsigned, signature=self._signer.sign(unsigned.payload()).hex())

@dataclass(frozen=True)
class Record:
    index: int; prev_hash: str; attestation_hash: str
    audit_head_ref: str; action_digest: str; trajectory_state: tuple
    trajectory_attestation: str; class_id: str; verdict_kind: str
    guard_id: str; punya_delta: float; vow_hash: str
    def hash(self):
        payload = (f"{self.index}|{self.prev_hash}|{self.attestation_hash}|"
                   f"{self.audit_head_ref}|{self.action_digest}|"
                   f"{list(self.trajectory_state)}|{self.trajectory_attestation}|"
                   f"{self.class_id}|{self.verdict_kind}|{self.guard_id}|"
                   f"{self.punya_delta}|{self.vow_hash}")
        return hashlib.sha256(payload.encode()).hexdigest()

def witness_zq_butterfly(q, a, b, w, ea, eb, idx):
    we = CoqWitness(name=f"zq_bf_{idx}_even",
                    statement=f"({a} + {w} * {b}) mod {q} = {ea}",
                    engine_output={"a": a, "b": b, "w": w, "ea": ea, "q": q},
                    engine_name=f"libzq/q={q}")
    wo = CoqWitness(name=f"zq_bf_{idx}_odd",
                    statement=f"({a} + ({q} - {w}) * {b}) mod {q} = {eb}",
                    engine_output={"a": a, "b": b, "w": w, "eb": eb, "q": q},
                    engine_name=f"libzq/q={q}")
    return we, wo
