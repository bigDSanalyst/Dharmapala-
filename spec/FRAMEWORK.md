# Framework

## Axioms
- A1 determinism
- A2 HMAC security
- A3 SHA-256 collision resistance
- A4 Coq kernel correctness
- A5 Lean kernel correctness
- A6 ML-DSA-65 EUF-CMA
- A7 Adversary secrecy

## Layers
1.  Compiled C engine (SHA-256 bound)
2.  Coq certificate: the engine's arithmetic and the verdict itself (`decision.py`)
3.  Lean certificate
4.  Co-signer re-run (runtime binding): re-runs the engine, reaches its own verdict, rebuilds the certificate and runs coqc on what it built, never on the file it was handed; signs the action digest, verdict and Vow hash
5.  Record chain: a record may cite only an attestation for its own action, verdict and Vow, and only once
6.  Audit chain (mutual anchoring)
7.  Compression (Landauer-correct)
8.  Adversary commitment (ML-DSA-65 / HMAC + Merkle)
9.  Trajectory DFA (co-signed verdict)
10. Cross-Sangha attestation (strict witness dedupe)
11. Doctor projection
12. E-process drift monitor

## Beyond the twelve
- Critic loop — Lean verifies Vow compliance during proposal, not after execution
- Adversary ensemble — N independent curricula; guard must satisfy all
- Guard nonce — per epoch the guard commits, a counterparty contributes randomness after seeing the commitment, then the guard reveals; the guard cannot grind a seed it cannot compute at commit time

## Not guaranteed
- Spec equivalence (algorithm identity proved, not binary-implements-spec)
- Always-trojans (consistent misimplementation)
- Environmental trojans (runtime-conditional behavior)
- Cross-Sangha global nullifier freshness
- ZK anonymity among witnesses
- Compilation correctness (Gap 2b)
- Full-execution certificates (Gap 2c)
- Observation soundness (the critic proves the Vow against the effects `observation.py` reports, not against what a plan actually does). Default-deny scope effects (read/write_outside_workdir, exec_unvetted, network_unlisted) now catch all seven exploit shapes in `tests/test_observation_gaps.py`, up from 0 of 7; `CAUGHT_BY` there pins which effect catches each one. What remains open:
  - the vetted commands and allowed hosts in `observation.py` are a policy, and each deployment should set its own
  - a dry run touches no filesystem, so it cannot see a symlink that leads out; the sandbox refuses those at execution time, after the critic has run
  - behaviour that differs between the dry run and the real run
  - the guard and co-signer share one observed effect set: the co-signer's verdict is independent, but its observation is not
- Routine actions (no class) are judged and refused when they carry a forbidden effect, but they get no certificate
- Timestamps (audit entries carry the local clock, which the writer chooses)
