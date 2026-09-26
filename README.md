# Dharmapala

A verified agentic guard framework. Every engaged guard decision carries a
Coq proof of its verdict: the certificate states which forbidden effects the
action carries, and coqc must accept it. A co-signer reaches its own verdict,
rebuilds that certificate and checks it itself, then signs the action, verdict
and Vow it vouches for. Routine actions are judged but not certified. What the
proofs rest on, and what they do not cover, is in `spec/FRAMEWORK.md`.

Runs end-to-end on Colab. Not audited. Not for production.

    python3 run_demo.py      # 12 layers, critic loop, ensemble, compression
    pytest -q

The demo prints `ALL CHECKS PASS` and exits 0 only when every layer actually
ran. When a toolchain is missing it still runs, falling back where it can, but
it ends with `DEGRADED`, names the layers that did not run and what to install,
and exits 1: a layer that did not run is not a layer that passed.

| Layer | Needs | Without it |
|---|---|---|
| Lean critic | `lean` on PATH, version in `lean/lean-toolchain` | the critic falls back to a Python check |
| Coq certificates | `coqc` (`apt install coq`) | attestations are signed as `coqc-unavailable` |
| ML-DSA-65 signatures | `pip install dilithium-py` | signers fall back to HMAC, which anyone able to verify can forge |
| Jail (real execution, traced) | `bwrap` and `strace` (`apt install bubblewrap strace`) | shell commands are recorded and never run |

CI installs all four, so a green CI run means all four ran.

## Guarding a real agent

    python3 guarded_agent.py "tidy up the notes in this directory" --workdir DIR --ledger ledger.json

Claude, through the Anthropic API, works on the task with four tools: `shell`,
`file_read`, `file_write` and `http_get`. It never executes anything itself. Each
call it proposes goes through the gate, in order:

1. The critic dry-runs it, and rehearses a shell command in the jail against a
   copy of the workdir. A call that would break the Vow does not run, and
   Claude is told which effect was forbidden.
2. The call runs for real. Shell commands run in the jail, traced. File tools
   stay inside the workdir unless the Vow says otherwise. `http_get` never
   reaches the network.
3. The guard judges what actually ran. The co-signer checks it against the run
   record with its own trace parser, and the decision is proven, signed and
   written to the ledger.
4. Claude sees the output only when the verdict is LAWFUL. A call whose real
   run broke the Vow was contained by the jail, but its output is withheld,
   because what it read is exactly what must not reach the model.

The default Vow forbids:
- the named harms: exfiltrating, destroying, dominating;
- reading sensitive paths;
- writing outside the workdir;
- reaching the network;
- a real run that did what its rehearsal did not (`diverged`).

`--vow FILE` replaces it. Credentials come from `ANTHROPIC_API_KEY` or
`ant auth login`.

## Verifying a ledger someone gave you

    python3 verify.py keys  ledger.json --json > pins.json   # once, when you have reason to trust it
    python3 verify.py check ledger.json --pins pins.json     # every time after

`check` exits 0 only when:
- every signer's key is pinned;
- the chains, signatures and checkpoints verify;
- doctor finds nothing BLOCK or DEGRADED.

Otherwise it exits 1 and names why. Keep the pins somewhere other than the
ledger: keys read from the file itself show only that the file agrees with
itself. A ledger signed with HMAC cannot be checked outside the process that
holds the key.

