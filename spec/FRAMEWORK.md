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
7.  Compression, commit-before-erase (`compression.py`): before erasing old records and audits, a signed checkpoint commits to each chain (Merkle root and head) and carries forward all the state the guard still reads (merit, proven classes, refusal counts, drift history, trajectory state). The erased entries go to an archive that `verify_archive` checks against the checkpoint by recomputing everything. Lossless by design: a learned or lossy summary could not be checked against what it replaced
8.  Adversary commitment (ML-DSA-65 / HMAC + Merkle)
9.  Trajectory DFA (co-signed verdict)
10. Cross-Sangha attestation (strict witness dedupe)
11. Doctor projection
12. E-process drift monitor

## Beyond the twelve
- Jail (`jail.py`): an accepted plan's shell commands really run, under bubblewrap (read-only root, a private /tmp, the workdir the only writable path, no network, own PID/IPC namespaces, no capabilities) and strace. The trace becomes effects in the Vow's vocabulary, attempts included, with paths resolved through symlinks, `cd` and directory fds. The guard certifies its verdict over what really ran. Anything beyond ordinary work that the dry run did not predict is also `diverged`. No jail, no execution
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
  - a dry run touches no filesystem, so it cannot see a symlink that leads out, a script's contents, a command inside `$(...)`, or a program's own file and socket calls. With the jail these are seen in the real run and judged there, and flagged `diverged` when unpredicted. Prevention for what the critic missed is the jail's containment, not the critic
  - the trace treats the dynamic loader's reads and libc's name-service files (`/etc/passwd` for `ls -l`) as the loader's doing. A plan that names them is caught from its arguments; a program that opens them itself is not, and any such program is `exec_unvetted` already
  - a program that detects it is being traced and behaves differently (an environmental trojan)
  - the jail needs bubblewrap's unprivileged user namespaces; where the host forbids them, nothing runs
  - the guard and co-signer share one observed effect set: the co-signer's verdict is independent, but its observation is not
- Routine actions (no class) are judged and refused when they carry a forbidden effect, but they get no certificate
- A loaded ledger (`Ledger.load`) is only as trustworthy as the keys it is checked against. Keys stored in the file prove only that the file agrees with itself. Pass `pinned={signer: key_id}`, or doctor reports `keys_from_the_file`. HMAC signers have no public key to store and must be supplied
- A toolchain that hangs or will not run has judged nothing. A timed-out or unrunnable coqc signs as `coqc-unavailable`, and a timed-out Lean critic accepts no plan and records no refusal. Neither counts as a layer that ran
- Timestamps (audit entries carry the local clock, which the writer chooses). A checkpoint's `hash()` is the natural thing to anchor externally; nothing anchors it yet
- Compression summaries are not proven up front. Each checkpoint commits to its fold step by step (`trace_root`). Anyone holding the archive can convict a wrong checkpoint with a fraud proof (`fraud.py`) that anyone checks without the archive, using `Ledger.dispute`. A convicted checkpoint makes the ledger fail `verify_integrity`, and doctor blocks on it. The succinct proofs (step, bind, order, final) carry O(log n) hashes, the entries of one step and one carried state. A compressor that commits a malformed trace forces the replay proof instead: O(n), still decisive, and it authenticates the entries against the checkpoint's roots before blaming the checkpoint. The trust model is one honest archive holder who looks. A compressor who withholds the erased entries entirely cannot be convicted, and `find_fraud` says so rather than reporting no fraud. A succinct validity proof (folding / IVC, e.g. Nova) would remove the watcher assumption; `Checkpoint.proof` is reserved for one
- Cross-Sangha publication reads live records: publish a class's witnesses before compressing them away
