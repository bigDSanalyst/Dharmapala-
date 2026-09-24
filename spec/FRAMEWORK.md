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
2.  Coq certificate
3.  Lean certificate
4.  Co-signer re-run (runtime binding)
5.  Record chain
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
- Observation soundness (the critic proves the Vow against the effects `observation.py` reports, not against what a plan actually does). `tests/test_observation_gaps.py` holds seven exploit shapes it misses today, as strict xfails: the baseline is 0 of 7 caught
- Refusal binding (a trajectory attestation on an audit entry is signed and checked, but the entry carries no action digest to bind it to)
- Timestamps (audit entries carry the local clock, which the writer chooses)
