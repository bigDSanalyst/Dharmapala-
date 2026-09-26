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
4.  Co-signer re-run (runtime binding): re-runs the engine, reaches its own verdict, rebuilds the certificate and runs coqc on what it built, never on the file it was handed; signs the action digest, verdict and Vow hash. When the effects come from a real run, the decision cites that run's record (`critic_loop.evidence_of`: calls, results, the jail's raw per-process trace and the events parsed from it, workdir, prediction) by digest, and the co-signer re-derives the effects from the record, refusing when they differ from the guard's account; the digest is signed. The co-signer does not use the parsed events: it reads the raw trace with its own parser (`witness.py`), a separate implementation sharing no code with `jail.parse`, so a fault in the guard's parser is a disagreement and a refusal, not a second signature. The two parsers agree event for event on honest runs, and a jailed call whose raw trace is missing or never shows the command is refused
5.  Record chain: a record may cite only an attestation for its own action, verdict and Vow, and only once
6.  Audit chain (mutual anchoring)
7.  Compression, commit-before-erase (`compression.py`): before erasing old records and audits, a signed checkpoint commits to each chain (Merkle root and head) and carries forward all the state the guard still reads (merit, proven classes, refusal counts, drift history, trajectory state). The erased entries go to an archive that `verify_archive` checks against the checkpoint by recomputing everything. Lossless by design: a learned or lossy summary could not be checked against what it replaced
8.  Adversary commitment (ML-DSA-65 / HMAC + Merkle)
9.  Trajectory DFA (co-signed verdict)
10. Cross-Sangha attestation (strict witness dedupe)
11. Doctor projection
12. E-process drift monitor

## Beyond the twelve
- Rehearsal (`critic_loop.rehearse`): before the critic accepts a plan, the plan runs in the jail against a throwaway copy of its workdir, and the critic judges what that run did as well as what the dry run predicted. The rehearsal then becomes the prediction the real run is held to for `diverged`. A script already in the workdir, which no dry run can see, is rehearsed like everything else. If the jail cannot rehearse, no plan is accepted
- Jail (`jail.py`): an accepted plan's shell commands really run, under bubblewrap (read-only root, a private /tmp, the workdir the only writable path, no network, own PID/IPC namespaces, no capabilities) and strace. The trace becomes effects in the Vow's vocabulary, attempts included, with paths resolved through symlinks, `cd` and directory fds. The guard certifies its verdict over what really ran. Anything beyond ordinary work that the dry run did not predict is also `diverged`. No jail, no execution
- Guarded agent (`guarded_agent.py`): a real model (Claude, through the Anthropic API, in a manual tool-use loop) proposes tool calls and never executes them. Each call goes through the critic (dry run, and rehearsal in the jail for shell), runs for real, and is judged by the guard and co-signer over what ran, then recorded. A refusal before running tells the model which effect was forbidden. A call whose real run broke the Vow ran contained, but its output is withheld from the model: the model is the channel that output would leave through. The model is untrusted by construction; the gate is the only path from its proposals to effects
- Anchoring (`anchoring.py`, ported from the syndicate mold's `tools/anchor.py`): each compression checkpoint is exported, entered in an append-only hash-chained log and stamped in Bitcoin with OpenTimestamps. `run` records after compression; `upgrade`, on a schedule, finds out, and never exits 0 when the calendars did not answer: unreachable is not "not yet confirmed". `verify.py check --anchors DIR` fails unless every checkpoint in the ledger is anchored, and only those, with the chain and exports intact; an unconfirmed anchor is reported, not failed
- Critic loop — Lean verifies Vow compliance during proposal, not after execution
- Adversary ensemble — N independent curricula; guard must satisfy all
- Guard nonce — per epoch the guard commits, a counterparty contributes randomness after seeing the commitment, then the guard reveals; the guard cannot grind a seed it cannot compute at commit time

## Not guaranteed
- What a guarded agent's lawful calls return goes to the model, and so to the API. The Vow decides what may be read; `read_sensitive_path` names only /etc/passwd, /etc/shadow, /etc/sudoers, /root and .ssh, so anything else readable in the sandbox that the Vow allows can reach the model
- A guarded agent's file tools are not jailed. They are held to the Vow by the critic before they run, and a relative path that resolves outside the workdir (through .. or a symlink) is refused, not followed
- Spec equivalence (algorithm identity proved, not binary-implements-spec)
- Always-trojans (consistent misimplementation)
- Environmental trojans (runtime-conditional behavior)
- Cross-Sangha global nullifier freshness
- ZK anonymity among witnesses
- Compilation correctness (Gap 2b)
- Full-execution certificates (Gap 2c)
- Observation soundness (the critic proves the Vow against the effects `observation.py` reports, not against what a plan actually does). Default-deny scope effects (read/write_outside_workdir, exec_unvetted, network_unlisted) now catch all seven exploit shapes in `tests/test_observation_gaps.py`, up from 0 of 7; `CAUGHT_BY` there pins which effect catches each one. What remains open:
  - the vetted commands and allowed hosts in `observation.py` are a policy, and each deployment should set its own
  - a dry run touches no filesystem, so it cannot see a symlink that leads out, a script's contents, a command inside `$(...)`, or a program's own file and socket calls. With rehearsal, the critic sees these before the plan runs for real. What a rehearsal still cannot promise is that the real run repeats it: a command that behaves differently on its second run, or on the real workdir rather than its copy, is caught only after the fact as `diverged`, under the jail's containment
  - the trace treats the dynamic loader's reads and libc's name-service files (`/etc/passwd` for `ls -l`) as the loader's doing. A plan that names them is caught from its arguments; a program that opens them itself is not, and any such program is `exec_unvetted` already
  - a program that detects it is being traced and behaves differently (an environmental trojan)
  - the jail needs bubblewrap's unprivileged user namespaces; where the host forbids them, nothing runs. Ubuntu 23.10 and later restrict them through AppArmor by default; a deployment allows them (`kernel.apparmor_restrict_unprivileged_userns=0`) or gives bwrap an AppArmor profile, and the jail probe names this when it is the cause
  - the co-signer re-derives a run's effects from its record with its own trace parser, so a guard that misreports what the record shows, or whose parser misreads it, is refused; but it trusts the raw trace. What the two parsers share is the event-to-effect mapping (`jail.effects_of`, the Vow's vocabulary), and a failed open is resolved through symlinks as the co-signer finds the filesystem, which is the same moment only when it co-signs right after the run. Raw trace lines forged before the guard saw them (a compromised executor or jail) are not caught without the co-signer re-executing the plan itself. An action with no run behind it carries no record, and there the guard's effect set is still the only observation
- Routine actions (no class) are judged and refused when they carry a forbidden effect, but they get no certificate
- A loaded ledger (`Ledger.load`) is only as trustworthy as the keys it is checked against. Keys stored in the file prove only that the file agrees with itself. Pass `pinned={signer: key_id}`, or doctor reports `keys_from_the_file`. HMAC signers have no public key to store and must be supplied
- A toolchain that hangs or will not run has judged nothing. A timed-out or unrunnable coqc signs as `coqc-unavailable`, and a timed-out Lean critic accepts no plan and records no refusal. Neither counts as a layer that ran
- Timestamps on records and audits (they carry the local clock, which the writer chooses). Checkpoints are anchored (`anchoring.py`): each is stamped in Bitcoin through OpenTimestamps, which bounds when it existed from above, never from below: a confirmed anchor proves the checkpoint existed by that block, not that it was made then. Everything a checkpoint commits to inherits that bound. Nothing between checkpoints is anchored, and an anchor is only as timely as whoever runs `anchoring.py run` after compressing
- Compression summaries are not proven up front. Each checkpoint commits to its fold step by step (`trace_root`). Anyone holding the archive can convict a wrong checkpoint with a fraud proof (`fraud.py`) that anyone checks without the archive, using `Ledger.dispute`. A convicted checkpoint makes the ledger fail `verify_integrity`, and doctor blocks on it. The succinct proofs (step, bind, order, final) carry O(log n) hashes, the entries of one step and one carried state. A compressor that commits a malformed trace forces the replay proof instead: O(n), still decisive, and it authenticates the entries against the checkpoint's roots before blaming the checkpoint. The trust model is one honest archive holder who looks. A compressor who withholds the erased entries entirely cannot be convicted, and `find_fraud` says so rather than reporting no fraud. A succinct validity proof (folding / IVC, e.g. Nova) would remove the watcher assumption; `Checkpoint.proof` is reserved for one
- Cross-Sangha publication reads live records: publish a class's witnesses before compressing them away
