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

### What actually happened

After the model's answer, the agent prints an account of every call, built
from the run records and never from the model:

    what actually happened (from the run record, not the model):
      lawful    read notes.txt -> "alpha\nbeta\n"
      lawful    wrote notes.txt <- "${response.body}gamma" (21 bytes)
      refused   file_read .env: refused before running: ... read_sensitive_path

That example is from the first live run. A 7B model wrote a placeholder into
the file and then reported the file's intended contents, and in a second run
it said "no credentials here" about a `.env` it had just been refused.

If the model writes a tool call into its answer as text instead of making it
(small local models do), the report names it: `note: the model wrote 1 tool
call(s) as text instead of making them (file_read notes.txt); they were not
run`. Nothing written that way is ever run.

With `--ledger`, the records are saved next to the ledger as
`LEDGER.runs.jsonl`: append-only and hash-chained, each run's record matching
the digest the ledger signed. The output of a call withheld from the model
is not written there either; only its digest is kept. To check the records
against the ledger:

    python3 verify.py check ledger.json --pins pins.json --runs ledger.json.runs.jsonl

### A model on your own hardware

    python3 guarded_agent.py "..." --workdir DIR --backend openai-compatible \
        --base-url http://localhost:8000/v1 --model NAME

Any server that speaks OpenAI-style chat completions with tool calls will
work: vLLM, Ollama, llama.cpp's server or LM Studio. If the server wants a
key, the environment variable named by `--api-key-env` supplies it (default
`OPENAI_API_KEY`).

The gate behind the model is the same whichever model it is. What changes is
where a lawful call's output goes: with a local model it stays on your
network. Local models emit malformed tool arguments more often than hosted
ones. Such a call is refused, never guessed at, and the model is told why.

### Policy

The Vow says which effects are forbidden. The policy (`policy.py`) says what
they mean in a given deployment:
- which paths are sensitive;
- which commands are vetted;
- which hosts are allowed, and which are exfiltration sinks;
- how many writes count as hoarding.

`--policy FILE` sets it:

    python3 guarded_agent.py "..." --workdir DIR --policy policies/strict.json

The built-in default is narrow. It treats only `/etc/passwd`, `/etc/shadow`,
`/etc/sudoers`, `/root` and `.ssh` as sensitive. `policies/strict.json` adds:
- `.env` files, and keys and certificates;
- cloud and container credentials, `.netrc` and git credentials;
- `/etc/ssh` and `/proc/*/environ`.

Start from it. Every key given in a policy file replaces its default rather
than adding to it, so a file says everything it means. A file that doesn't
parse is refused.

Each verdict names the policy that judged it. The run record carries the
policy, and the attestation signs its hash. The co-signer vouches under exactly
one policy and refuses a decision made under any other.

## Is the jail really containing anything?

    python3 containment_mutants.py

This breaks the jail one bubblewrap flag at a time and checks that a
containment probe catches each break as an escape. It exits 0 only when
every break is caught, and it names each flag no probe here can observe, with
the reason. CI runs it as an unprivileged user and as root.

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

