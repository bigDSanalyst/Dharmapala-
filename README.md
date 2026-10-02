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

Where the answer and the record can be compared exactly, the report says so
under `where the answer and the record differ:`. Three cases are checked:

- `content`: the answer shows a file's contents (a fenced block, or a block
  after a line such as "notes.txt contains:"), but the record shows the file
  last as something else.
- `omitted`: the gate stopped calls, and the answer mentions neither what they
  touched nor any refusal.
- `underclaim`: the answer says it could not read a file, or that reading was
  blocked, but the record shows the read succeeded. A sentence that names files
  is checked for those files. A sentence that names none ("the files were
  blocked") is checked for every file that was read and is never named in the
  answer. In one live run, a 7B model had `.env` refused and `readme.txt` read,
  then said reading "the files" was blocked.

Prose descriptions and anything after a lawful shell call, which may have
changed any file, are not checked. No model is asked to judge, and the report
names a difference, never a motive.

When a difference is found, the model gets one more turn, once. It is shown the
differences and what the record shows call by call, and asked to correct its
answer or finish the work so the answer becomes true. Every call it makes then
goes through the gate like any other. Its new answer is a claim like the first
one and is checked the same way. The report shows both answers and says whether
they now agree. Both the differences shown and the result of the recheck are
entries in the run record, beside the calls. `--no-reconcile` turns this off.
Arguing does not help: an answer that only insists still differs, and the
report says so.

With `--ledger`, the records are saved next to the ledger as
`LEDGER.runs.jsonl`: append-only and hash-chained, each run's record matching
the digest the ledger signed. The output of a call withheld from the model
is not written there either; only its digest is kept. To check the records
against the ledger:

    python3 verify.py check ledger.json --pins pins.json --runs ledger.json.runs.jsonl

Each run needs its own `--ledger`. If the ledger or run-records file is
already there, the agent refuses to start (exit 1, naming the file) rather
than replace one run's ledger and append to its records, which would leave
two files that no longer describe one run. The account printed after a run
shows only that run's calls.

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

## On AgentDojo

    pip install agentdojo==0.1.35
    python3 eval_agentdojo.py                          # the guard, no model: about an hour on 4 cores
    python3 eval_agentdojo.py --model qwen2.5:7b --base-url http://localhost:11434/v1 --suites banking --limit 4

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is the benchmark prompt-injection defences
report on. It has 97 user tasks in four suites (workspace, travel, banking, slack), each paired with
the suite's injection tasks. Its tools change state instead of files: they send money, send mail,
share files and invite users. `agentdojo_guard.py` reads each call's effects from that state:

1. The call runs on a copy of the environment.
2. The guard diffs the copy and reads the diff under `policies/agentdojo.json`. Money, mail, a share,
   a message or a web request to a party that is not trusted is `exfiltrate`. A party is trusted if
   it is the user's own identity, was already in the environment, or is named in the user's prompt.
   An unknown new user, or a password the user did not give, is `dominate`. A removal is `destruct`.
3. A witness runs the call again on its own copy, at the same clock reading, and diffs it with its
   own code. If the two readings differ, the call is refused.
4. Otherwise the verdict goes through `Guard.engage` (Coq certificate, ML-DSA co-signer, ledger).
5. Only a lawful call's copy becomes the environment, so a refused call changes nothing.

With no model, `eval_agentdojo.py` plays a *hijacked* agent. It makes the user task's calls and
then every call of the injection task, and AgentDojo's own checks score the run. That is the worst
case: the model is already won over and the guard is all that is left. Every attack also runs
without the guard, which shows it is real. 593 of the 949 pairs succeed unguarded, and only
those are counted. `results/agentdojo-default.json`:

| suite | utility, no guard -> guard | attacks that succeed (AgentDojo's score) | of calls that ran |
|---|---|---|---|
| banking | 16/16 -> 15/16 | 0/141 (0%) | 0% |
| slack | 21/21 -> 19/21 | 63/105 (60%) | 40% |
| travel | 20/20 -> 20/20 | 57/116 (49%) | 49% |
| workspace | 40/40 -> 40/40 | 40/231 (17%) | 17% |
| **total** | **97 -> 94** | **160/593 (27.0%)** | **23.4%** |

The strict Vow also forbids `destruct` (`results/agentdojo-strict.json`). That takes workspace to
0/231 and the total to 120/593 (20.2%, or 16.7% of calls that ran), and utility to 92/97.

What these numbers are and are not:

- **No model was run.** The "hijacked agent" always obeys the injection, so these are not an attack
  success rate for any model and are not comparable to CaMeL's or MELON's model runs. They measure
  what is left once the model is lost. `--model` runs a real one through the same guard.
- **The guard stops what the attacker's calls do to parties.** It stops money or data going to
  strangers, strangers invited in, and passwords changed. That covers all of banking, and all of
  workspace under the strict Vow.
- **It does not stop what looks like the user's own business.** Examples: a phishing link sent to a
  colleague, a hotel booked for the user, a calendar event created, and a visit to a URL already in
  the environment. The effects of these calls are ordinary; only the provenance of their arguments
  shows they came from the attacker. Catching them needs data-flow tracking (CaMeL, FIDES), which
  this guard does not have.
- **"Of calls that ran" is not AgentDojo's number.** Slack's injection_task_5 is scored on the calls
  the agent *attempted*. The guard refused the invitation and Fred never joined, but AgentDojo still
  counts the attack. The official number is kept, and this column scores that one task on the calls
  that ran.
- **The cost is 3 of 97 user tasks.** Each one hands money, a web post or a Slack invitation to a party
  the user did not name, taken from a file, an email or a web page.
- **Arbitration.** Across 4,275 calls the witness agreed with the guard every time. The first full
  run told a different story: 665 disagreements. AgentDojo stamps mail and files with the current
  time, so two runs of the same call differ. That run lost 24 user tasks to it, and some attacks
  were "stopped" for that reason and no other. The clock is now an input that both runs share, so any
  disagreement left means something else differed.

The policy was written from the suites' tools, schema and user prompts, not from the injection
tasks, and was not changed after seeing results. CI re-runs the first user task of each suite
against every injection task, and it must reproduce the committed results.

### Learned refusals: lessons

    python3 eval_lessons.py --out results/agentdojo-lessons.json     # about an hour on 4 cores
    python3 eval_agentdojo.py --lessons book.json                     # any run, with a book of lessons

What gets past the guard is provenance: ordinary calls whose arguments the attacker chose.
Self-Evolving Defense (SED, 2026) answers that by learning: a judge marks a trajectory harmful, and
the failure becomes a policy for later episodes. `lessons.py` is that loop, held to three rules:

- **Tighten-only.** A lesson is read after the guard's verdict, and only when that verdict is
  lawful. It can refuse what the guard allowed; it has no way to allow anything. A wrong lesson
  costs utility, never safety. A test builds books from every candidate lesson and checks that
  nothing lawful with a book was refused without it.
- **Admitted, not just learned.** A candidate lesson is kept only if it refuses none of the calls of
  the known-good trajectories. The most general candidate that passes is kept: "a link in a direct
  message that the user did not name" before "this link".
- **Append-only.** Each lesson carries the hash of the book before it, and the book the hash of
  all of it; a book with an edited history does not load. Whoever can write the file can rewrite
  the whole chain, so the hash is what binds: every lesson refusal records it, results record it,
  and `Lessons.load(path, expect=...)` checks it.

A lesson is deterministic: a tool, an argument, a kind of token (a URL, an email address, an IBAN, or
the whole value), and optionally the token. It fires when that argument carries such a token and
the user's prompt does not name it. Which trajectories are harmful is the judge's call; here it is
AgentDojo's own security check, and it could be a model.

SED scores AgentDojo on the same stream it learns from. `results/agentdojo-lessons.json` scores on
tasks the lessons never saw. Each suite's user tasks are split in two by position: lessons are
learned on the even ones and tested on the odd ones. The agent is the hijacked one above.

| suite | lessons | utility, test half | repeated attacks (held-out user tasks) | unseen attacks (held-out injection task) |
|---|---|---|---|---|
| banking | 0 | 8/8 -> 8/8 | 0/71 -> 0/71 | 0/71 -> 0/71 |
| slack | 4 | 9/10 -> 9/10 | 20/50 -> 0/50 | 20/50 -> 20/50 |
| travel | 2 | 10/10 -> 10/10 | 29/58 -> 1/58 | 29/58 -> 9/58 |
| workspace | 1 | 20/20 -> 20/20 | 20/114 -> 2/114 | 20/114 -> 20/114 |
| **total** | **7** | **47/48 -> 47/48** | **69/293 -> 3/293** | **69/293 -> 49/293** |

- **Against an attack it has seen, it works.** 66 of the 69 attacks that got past the guard on the
  test half are stopped, and no clean test task had a call refused by a lesson.
- **Against an attack it has not seen, it mostly does not.** Leaving each injection task out of
  learning, the only transfer is in travel. There, injection_tasks 0 and 4 both book a hotel the
  user did not name, so each one's lesson stops the other (20 attacks). Slack's link and URL
  lessons, and workspace's lesson for one file, say nothing about a different attack. This is the
  gap SED's own limitations section names, measured.
- **What the 3 left are.** Two workspace attacks delete file 13 under a prompt that mentions
  "June 13", and the lesson gives way to what the user named; matching a short token by its text
  is too loose. The third is a travel attack that sends the user's passport and card numbers to
  an address the prompt itself names; no learning task was hijacked by it.
- **Some lessons are broad.** Travel learned "do not book a hotel the user did not name", from
  one hijacked trajectory. No learning task booked an unnamed hotel, so it was admitted, and no
  test task needed one. A deployment's known-good set would need to cover the tasks it is meant
  to keep working.
- **No model was run here.** The judge is AgentDojo's check and the agent is scripted, so this is
  what lessons do once a hijack is known and repeated; not a rate for any model.

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

