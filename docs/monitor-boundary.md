# Monitor boundary: design

Status: design for Phases 2 to 4. Written against `main` at `676760e` (2026-11-20) and updated
at `bb926a5` (2026-11-21), after Phases 0 and 1 landed in #25 to #29. Each result marked *verified*
names the commit it was run against, on Linux 6.18 with bubblewrap, strace, Coq 8.18, Lean 4.14.0
and ML-DSA-65 installed. At `676760e`, `main` was green there: 592 passed, 20 skipped (agentdojo,
the anthropic SDK and ots not installed), with `DHARMA_REQUIRE_JAIL=1`.

Supporting file, in `docs/monitor-boundary/`:

- `repro_openat2.py`: end-to-end reproduction of finding F1 (reads only a dummy file). The model
  receives the file at `676760e` and not on `main` since #26. `tests/test_untraced_reads.py` is the
  regression test CI runs.

The Phase 1 prototype (`jail_landlock.py`) is not included: `confine.py` replaced it in #26.

## 1. Where the boundaries are

| Component | Runs in | Can reach |
|---|---|---|
| The model (the agent) | remote, behind the API | this host only through `Gate.run` |
| `Gate`, critic (Lean), guard, ledger, `observation`, trace parsing (`witness`) | one Python process: under Landlock from `guarded_agent`'s command line (`gate_confine.py`, Phase 2 slice 3b) | read and execute on the system, Python, the repository and the toolchains; read on the certificates TLS trusts and the model's stored login; its scratch; the ledger files. Not the workdir |
| `CoSigner`, `TrajectoryCoSigner` | the same process | both ML-DSA-65 signing keys |
| The monitor (P0): `file_read`, `file_write`, jail spawning, the session record | its own process (`monitor.py`, Phase 2 slice 2), undumpable | the workdir's pinned descriptor (`cw_vfs`, #28) and the `Monitor` key, which the gate never holds |
| `shell` commands | bubblewrap jail with Landlock and seccomp (`confine.py`, #26, #27), traced by strace | the system directories and listed `/etc` entries, read-only; the workdir, read-write |

At `676760e` the jail bound the whole host root read-only, and the file tools resolved paths in
userspace.

What already holds, and should be kept as it is:

- `Gate.run` accepts only the four tools, with exactly their argument names and string values.
- Untrusted code only ever runs inside the jail: `--unshare-all`, `--cap-drop ALL`, `--clearenv`,
  `--die-with-parent`, a private `/tmp`, Landlock and seccomp. `containment_mutants.py` breaks each
  one and checks that a probe catches it, testing the bubblewrap layer and the `confine.py` layer
  each with the other switched off.

So the model cannot reach `Sandbox`, the workdir descriptor or a key directly. Of the two boundaries
inside the host that needed work, one is closed for containment and one is open:

1. **Jail → observation.** The guard judges what strace shows, and strace is told to show 15 syscalls.
   Since #26, the calls that open or execute a file without passing through one strace shows
   (`openat2`, `execveat`, `io_uring_*`, file handles) fail, and Landlock bounds what any call can
   reach (F1). The refused calls are traced too, and each attempt is recorded as a `refused` event.
   It is telemetry, not an effect, so a run that tried one is still judged `lawful` (§5,
   "Quarantine stream").
2. **Parsing → keys.** Open (F2): the process that parses attacker-influenced bytes (traces, file
   contents, model output) also holds both signing keys.

## 2. Findings

| | Finding | Status |
|---|---|---|
| F1 | Reads through untraced syscalls never reach the guard | fixed in #26 |
| F2 | Signing keys share an address space with the parsers | open: Phase 3 |
| F3 | Witnesses are not bound to the session's workdir | fixed in-process: `monitor.py` (Phase 2) |
| F4 | `critic_loop.execute` dispatches by name without an allowlist | fixed: `tools.dispatch` (Phase 2) |
| F5 | cw_vfs is not in `main`, and the versions in circulation have diverged | resolved in #28 and #29 |
| F6 | Host Unix sockets are reachable from the jail | fixed in #27 |

Each finding below is written as found, at `676760e` unless it says otherwise, with its fix after it.

### F1. Reads through untraced syscalls never reach the guard (verified, end to end)

- `jail.SYSCALLS` traces `openat`, `open`, `execve` and others, but not `openat2`,
  `io_uring_setup`/`io_uring_enter`, or `execveat`.
- The jail mounts the host root read-only (`--ro-bind / /`), so anything the user can read is reachable.
- The default Vow forbids `read_sensitive_path` but not `exec_unvetted` or `read_outside_workdir`;
  no Vow in the repository forbids those two.

Result, with the default Vow and a scripted model (`repro_openat2.py`):

| Shell command | Outcome | Model receives the key |
|---|---|---|
| `cat ~/.ssh/<key>` (control) | refused before running (`read_sensitive_path`) | no |
| `python3 r.py`, where `r.py` opens the same file with `openat2` | **lawful** | **yes** |

Every layer agrees, because every layer reads the same trace: the critic's rehearsal, the real run,
the guard, the co-signer's own parser, and the co-signer's replay. Independent re-derivation cannot
catch what the evidence never contained. This is a confidentiality bypass within the threat model the
AgentDojo evaluation tests (a prompt-injected model).

**Fix (#26).** Landlock inside the jail limits reading and executing to the system directories,
whatever syscall makes the call. seccomp makes `openat2`, `execveat`, `io_uring_*`,
`open_by_handle_at` and `name_to_handle_at` fail with ENOSYS. At `bb926a5`, `repro_openat2.py`
gives: control refused; the openat2 run `lawful`, and the model receives no key material (verified).
The run is still judged `lawful` because the refused call is not in the trace: containment holds,
but the attempt goes unseen. Since then, the attempt is recorded as a `refused` event (§5), and the
run is still judged `lawful`.

### F2. Signing keys share an address space with the parsers

`guarded_agent.setup` builds `CoSigner(default_signer(...))` and `TrajectoryCoSigner(...)` in the same
process that parses strace text (`witness.py`, `jail.parse`), file contents and model output. A logic or
memory-safety bug in any of that code can make the co-signer sign anything, or leak a key for later use.
The co-signer's independence is logical, not a separate process.

### F3. Witnesses are not bound to the session's workdir

`verify_witness_against_call` (in the cw_vfs branch) checks a witness against its call and against
itself. Nothing compares `root_dev`, `root_ino` or `fd_realpath` with the workdir the run was for, so a
well-formed witness from any root verifies.

Still true at `bb926a5`, where the function is in `cw_vfs.py` (#28). The session header (§5) closes it.

**Fix (Phase 2, slice 1).** `monitor.py` signs a session header naming the workdir and its root,
chains every real call and signs a checkpoint at the end of each run (§5). The co-signer refuses a
run whose witness is from another root, or names a file outside the header's workdir, and so does
`verify.py --runs`. Until the monitor is its own process (slice 2), the gate's process holds the
monitor's key, so a fault there can still sign whatever the monitor can.

### F4. `critic_loop.execute` dispatches by name without an allowlist

`getattr(real, tool)(**kwargs)` runs any `Sandbox` attribute the plan names. Through `Gate` this is safe,
because `Gate.run` validates the name first. Any other caller is trusted blindly: a plan naming
`__init__` would re-root the sandbox. `_OneCall.act` has the same pattern.

Verified at `9a5b029`: a plan of `file_write first.txt`, `__init__` with another workdir, then
`file_write planted.txt` writes `planted.txt` into the other directory. `__init__` also resets the
sandbox's `calls`, so the record keeps only the planted write, judged as an ordinary write inside the
workdir, and the first write is gone from it.

**Fix.** Both call sites go through `tools.dispatch`, a fixed table of the four tools and exactly
their arguments (`guarded_agent.ARGS` is the same table, and a test keeps them in step).
`critic_loop.execute` checks every step before running any, so a plan with one bad step runs nothing
(`tests/test_dispatch.py`).

### F5. cw_vfs is not in `main`, and the versions in circulation have diverged (verified)

There are two lines:

- **v2 patch** (`cw_vfs_dharmapala_final_v2.patch`): integration with `tools`, `critic_loop`, `replay`,
  `guard` and `to_coq_witness`, keyed `capability_witness`. It binds a write's witness to the call's own
  content, checks `leaf_mode`, fsyncs the parent directory, and skips temp files when cloning.
- **D12 line** (`cw_vfs_fixes.diff` and the 68-test adversarial suite): `mkdir_confined`; clone with
  directories first, exact modes, and empty directories kept; dup'd `scandir` descriptors; and no
  `st_dev` equality checks, so that overlayfs works.

Against `main`, the v2 patch applies cleanly but:

| Check | Result |
|---|---|
| Its own unit tests | 4 / 4 pass |
| Adversarial suite (D12 line) | 59 pass, 9 fail: `mkdir_confined` missing (5), clone fixes missing (2), Coq definition count (1, from `leaf_mode`), write witness binding (1, where v2 is the stricter and correct rule) |
| Repo tests: evidence, replay, rehearsal, binding, signatures, witness, runs | 39 fail, 68 pass |
| … after adding `Sandbox.logical_workdir` (35 of the 39) | 3 fail, 104 pass |

Two of the remaining three are `test_evidence` fixtures without witnesses (expected under the new rule).
The third is a real regression: `rehearse` now records the *real* workdir as the evidence path while the
jailed shell runs in the scratch copy, so every file a rehearsed command writes is judged
`write_outside_workdir` and refused before running.

The v2 line also still has the `st_dev` checks, so on overlayfs (Colab, Docker) it would refuse every
file operation, which is the bug D12 fixed.

**Resolution (#28, #29).**
- #28 took the v2 patch as the base and ported D11 and D12 from the D12 line, keeping v2's stricter rules.
- It fixed the rehearsal regression by mounting the scratch copy at the workdir's own path.
- CI runs the overlay case for real, as root, on an overlay mounted with `xino=off` so the per-inode
  devices appear.
- #29 adopted the adversarial suite and changed its two tests that encoded the older rules.

### F6. Host Unix sockets are reachable from the jail (verified, after #26)

The jail still bound the whole host root read-only, and Landlock does not stop a `connect` to a socket
file. So a command could talk to any host daemon whose socket it could see, such as an SSH or GPG agent
or Docker: a test socket under `$HOME` received data sent from inside the jail. Both trace parsers
skipped every `AF_UNIX` connect as "not the network", so the guard did not see it either.

**Fix (#27).**
- The binds are narrowed to the system directories and listed `/etc` entries.
- seccomp makes `socket(AF_UNIX, …)` fail with EPERM. It compares only the low 32 bits of the domain,
  as the kernel does. `socketpair` still works.
- Both parsers report connects to named sockets.

## 3. Target architecture: privilege separation

The pattern is OpenSSH's privsep: the process that handles untrusted input holds no authority, and
the process with authority handles no untrusted input.

```
        model API
            │
   ┌────────▼─────────┐   IPC (§4)    ┌──────────────────────────┐
   │ P1  Gate          │──────────────▶│ P0  Monitor               │
   │ critic, guard,    │◀──────────────│ workdir root fd (cw_vfs)  │
   │ trace parsing,    │  results +     │ jail spawning (P3)        │
   │ observation       │  chain records │ hash chain + ML-DSA key   │
   │ no key; no workdir│               │ parses nothing untrusted  │
   └────────┬─────────┘               └────────────┬─────────────┘
            │ evidence + signed checkpoint          │ spawns
   ┌────────▼─────────┐               ┌────────────▼─────────────┐
   │ P2  Co-signer     │               │ P3  Jail (per shell call) │
   │ own ML-DSA key;   │               │ bwrap + Landlock +        │
   │ own parser;       │               │ seccomp, traced           │
   │ replay via own P0 │               └──────────────────────────┘
   └──────────────────┘
```

**P0, Monitor.** Small and privileged. It holds the workdir root descriptor (`CapabilityDirJail`) and
the monitor's ML-DSA-65 key, and it:

- performs `file_read` and `file_write` through cw_vfs;
- spawns P3 for `shell`;
- creates scratch copies for rehearsal and replay with `clone_confined_snapshot`;
- appends every operation to a hash chain and signs checkpoints.

It stores each raw trace and puts the trace's hash in the chain, but never parses it.

*As built (slices 2 and 3a):* `monitor.py serve`.
- **Every jail run and every copy of the workdir happens in a monitor process:**
  - the real call;
  - the critic's rehearsal, in a copy space of the gate's monitor;
  - the co-signer's snapshot and replay, in copy spaces of a second monitor process that is the
    co-signer's own ("replays through its own P0"), so a jail that lies to the gate does not also lie
    to the replay.
- **The gate asks its monitor whether the jail works** (`jail_status`), and runs no jail itself.
- **Copies are named for what they are for** (`rehearsal_`, `snapshot_`, `replay_`), as the gate's
  own copies were. A command can still tell a copy by its mount's source, as before (§2, the
  environmental-trojan limit).
- **Started by the gate, not the other way round.** This proposal had P0 create the socketpair and P1
  inherit it. The gate starts P0 instead, so that a library caller or a test can use it without
  forking itself.
- **First thing it does:** P0 makes itself undumpable (`PR_SET_DUMPABLE` 0), so no process of the same
  user, its parent included, can ptrace it or read its memory. It also asks to die with its parent.
- **Peer check:** it refuses a peer whose `SO_PEERCRED` is not its parent.
- **Key:** it generates its ML-DSA-65 key itself and sends only the public half. Without ML-DSA-65 it
  refuses to start, since a shared-secret key would have to be shared with the gate. The monitor then
  runs in the gate's process under the same HMAC fallback as the other signers.
- **Shell:** P0 runs the jail (`jail.run_raw`) and returns the raw trace unread. The gate parses it
  (`jail.parse`) and adds the events. A record's result hash leaves them out, because they are the
  gate's reading, not the monitor's output. If the trace never shows the command starting, the gate
  records no events, and the co-signer's own reading (`witness.events_for`) refuses the run.

P0 never applies Landlock to itself while it is live. The kernel refuses `mount(2)` to a process under
a Landlock ruleset that restricts the filesystem, so a Landlocked P0 could start no jail (verified, §5).

**P1, Gate.** Everything that reads untrusted bytes: the model loop, critic, trace parsing,
observation and guard. It requests operations from P0 and holds no key. Landlock gives it no access to
the workdir at all, so the only way to touch the workdir is through P0. It gets read access to the
repository and toolchains, plus its own scratch directory. P1 starts no jail, so Landlock costs it
nothing.

*As built (slice 3b):* `gate_confine.py`, applied by `guarded_agent`'s command line once its monitors
run. Landlock grants and cannot subtract, so the workdir is simply not among the grants.
- **Read and execute:** the system directories, Python's installation and import path, the repository,
  and the Lean and Coq toolchains.
- **Read:** the certificates TLS trusts, each file or directory of them: where the environment names
  them (`SSL_CERT_FILE` or `SSL_CERT_DIR`, a proxy's CA bundle, say) or Python finds them (OpenSSL's
  defaults, certifi).
- **The model's stored login:** with the anthropic backend and no key or token in the environment, the
  SDK reads the login `ant auth login` stored (`~/.config/anthropic`, or `ANTHROPIC_CONFIG_DIR`), and
  refreshing a token replaces its credentials file. So that directory stays readable, and in its
  `credentials/` directory the gate may make, write, replace and remove files.
  - A compromised gate could therefore read the stored refresh token, and replace or remove the
    stored credentials. It cannot change the profile's config, so it cannot change where they are
    sent. It already holds the token it calls the model with; keeping the model's credentials out of
    P1 is not part of Phase 2.
  - A profile whose `credentials_path` points elsewhere is not granted: the SDK fails to read it,
    before any refresh, and the agent stops.
  - A workload identity token named by `ANTHROPIC_IDENTITY_TOKEN_FILE` stays readable as the file it
    was at startup. A token rotated by replacing the file, as Kubernetes does with a projected token,
    is not readable once it has been replaced.
- **Everything:** a private scratch directory, which becomes `TMPDIR`. A reaper, started before the
  restriction and given only that path, removes it when the gate exits, however it exits.
- **Read and write:** `/dev`'s device files, and the ledger and run-records files. These are made
  first, as files, so no directory stays writable.
- **Refused at startup:** a workdir inside any granted path, or holding one: the ledger, say, or the
  stored login, whose directory a refresh writes in.
- **Checked afterwards:** that the gate cannot open the workdir and holds no descriptor into it,
  since Landlock does not revoke one already open. Either failing is a refusal.
- **Unconfined, with a warning:** without Landlock, or without ML-DSA-65, when the monitor runs in the
  gate's own process.
- **Library callers** (`setup()`, the tests) are not confined. Landlock is for good, so
  `tests/test_gate_landlock.py` confines processes of its own.

**P2, Co-signer.** A separate process with its own key. Its input is an evidence bundle plus P0's signed
checkpoint. It verifies the chain, the signature and each witness's binding (§5), re-derives effects with
its own parser, and replays through its own P0 instance. Its output is the ML-DSA-65 attestation, as
today. The trajectory co-signer follows the same pattern.

**P3, Jail.** The bubblewrap jail as it is in `main` (#26, #27). `confine.py` runs inside bwrap, after
the mounts and before the command, and applies:

- **Landlock:** read and execute under `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc` and `/proc`; full access
  under the workdir and the jail's own `/tmp` and `/dev`.
  - If Landlock is unavailable, the jail refuses to run, the same way it refuses without bwrap: it
    prints `dharma-jail: …` and exits 126, and `jail.run` raises `JailUnavailable`.
  - It is enforced at the kernel's LSM layer whatever syscall the command uses, so it closes F1 for
    containment.
- **seccomp:** `openat2`, `execveat`, `io_uring_setup`/`io_uring_enter`/`io_uring_register`,
  `open_by_handle_at` and `name_to_handle_at` fail with ENOSYS. So do calls under a foreign arch or the
  x32 ABI.
  - Programs fall back to calls the trace shows, as on a kernel without these calls. (This proposal
    first said EPERM.)
  - Denying the calls keeps the trace complete for judging what happens inside the allowed space.
  - `socket(AF_UNIX, …)` fails with EPERM (F6).

bwrap itself provides:

- **Narrower binds** in place of `--ro-bind / /`: the system directories, plus listed `/etc` entries
  (loader, name service, locale, certificates). `containment_mutants.py` tests them with `confine.py`
  switched off, so they hold as defence in depth.

## 4. IPC between P1 and P0

- **Transport:** an `AF_UNIX` `SOCK_SEQPACKET` socketpair created by P0 and inherited by P1. P0 checks
  `SO_PEERCRED`.
- **Framing:** one canonical JSON object per message (sorted keys, UTF-8), at most 1 MiB. Anything else
  closes the connection.
- **Requests:** `{"v": 1, "seq": n, "op": OP, "args": {...}}`. `OP` is one of:

  | Op | Args |
  |---|---|
  | `open_space` | `{"kind": "real" \| "rehearsal" \| "replay", "source": space?}` |
  | `file_read` | `{"space", "path"}` |
  | `file_write` | `{"space", "path", "content", "mode"}` |
  | `shell` | `{"space", "cmd"}` |
  | `http_get` | `{"url"}` (never fetches, as today) |
  | `checkpoint` | `{"space"}` |
  | `close_space` | `{"space"}` |

  Argument sets are exact, as in `guarded_agent.ARGS`: unknown keys or wrong types are rejected.
  Dispatch is a fixed table, never `getattr`.
- **Responses:** `{"v": 1, "seq": n, "ok": bool, "result": {...}, "record": {"index", "prev", "hash"}}`.
  P0 numbers and hashes every record; P1 never constructs one.
- **Compatibility:** P1 keeps the `Sandbox` interface (a client wrapping the socket), so
  `critic_loop` and `guarded_agent` change little.

*As built (slice 2):* `monitor.RemoteMonitor` and `RemoteSandbox`, with two differences from the above.
- **Transport:** frames are length-prefixed on a `SOCK_STREAM` socketpair: a 4-byte big-endian length,
  then one canonical JSON object. `SOCK_SEQPACKET` caps a message at the socket's send buffer, which
  is 212992 bytes by default (verified: a 300 KB message fails with `EMSGSIZE`), and a jailed run's
  raw trace can be longer. Requests are capped at 1 MiB; a larger length is refused before its payload
  is read.
- **Operations:** `file_read {space, path}`, `file_write {space, path, content}`, `shell {space, cmd}`,
  `http_get {space, url}`, `checkpoint {}`, `open_space {source, kind}`, `close_space {space}` and
  `jail_status {}`.
  - **Spaces:** a space is `real`, or a copy that `open_space` made from `real` or from another copy
    (`clone_confined_snapshot`), mounted at the workdir's path when a command runs in it.
  - **What is recorded:** only the real space's calls go into the session chain. A copy's calls change
    nothing real.
  - **Protocol violations:** an unknown space, closing `real`, or a `kind` other than `rehearsal`,
    `snapshot` or `replay`. Copies are capped at 64.
  - `file_write` takes no `mode`.
  - `checkpoint` answers with the run's session block (§5).
- **Violations:** a request that is not exactly the next `seq` and a known operation with its
  arguments, all strings, ends the monitor (exit 3). The gate then refuses every call: "the monitor
  process is gone". Slice 4 makes that a recorded tripwire.

## 5. Records, checkpoints and binding

- **Session header**, signed by P0 at start: session id (128 random bits), workdir realpath, root
  `(dev, ino)`, resolve mask, policy hash, Vow hash, monitor code hash, monitor public key id, start
  time, and (once Phase 4 lands) the endowment `(n, k₀, c)`.
- **Record `i`:** `{index, prev, session, op, args_sha256, result_sha256, time}`.
  Its hash is SHA-256 of the canonical JSON, and `prev` chains it to record `i − 1`. The result hash
  covers the call's witness and raw trace. (This section first listed them as separate fields.)
- **Checkpoint:** ML-DSA-65 over `(session, index, head_hash)`, at the end of each tool call. One
  signature covers every earlier record through the chain.
- **Verification** (in `verify.py` and P2), on top of `verify_witness_against_call`:
  - the checkpoint signature verifies;
  - the chain recomputes;
  - each witness's `(root_dev, root_ino)` equals the header's;
  - each `fd_realpath` lies under the header's realpath.

  Together these close F3.

**As built (slice 1, in-process).** `monitor.py`; the signer is `Monitor`, registered in the ledger
and pinned like the other signers.
- **The session block:** each run's evidence carries one. It holds the signed header, the checkpoint
  the run started from, the run's records and the checkpoint it ended on. The run records file keeps
  the block even for a withheld call: it holds only hashes, and without it the chain would have a gap.
- **The co-signer** checks every run against the block before vouching:
  - the signatures;
  - the chain from one checkpoint to the next;
  - that the records are exactly the run's calls;
  - that the header is for its workdir and policy;
  - the witness binding.
- **`verify.py --runs`** checks the same offline, plus continuity: each run must start at the
  checkpoint the session's previous run ended on, so a dropped run shows even when its output was
  withheld.
- **Not yet:** the co-signer keeps no state between calls, so it cannot see a run hidden from it
  between two it was shown. `verify.py` sees that; a stateful co-signer is Phase 3 (P2).

**Why not BLS12-381 aggregate signatures.** Dharmapala signs with ML-DSA-65, which is post-quantum.
BLS is pairing-based and falls to a quantum attacker, so signing witnesses with it would downgrade the
whole attestation path. With a single monitor, the hash chain plus one ML-DSA signature per checkpoint
already gives "one signature covers many witnesses". Aggregation pays off only with several independent
signers on the same records (for example a quorum of monitors). Revisit it then, alongside a
post-quantum signature rather than instead of one.

### Quarantine stream and terminal capture

P0 records refused tool calls and tripwire events to a separate, append-only quarantine stream
(`quarantine/<session_id>/`) rather than the main `BoundedDebt` ledger.
- P0 performs zero parsing of traces or staging payloads; it only hashes, timestamps, writes and signs.
- All offline forensic extraction, clustering and pivot-graph analysis run in an unprivileged process
  holding no signing keys and no workdir descriptor.

#### Canonical JSON record (`QuarantineRecord`)

```json
{
  "v": 1,
  "session": "<128-bit hex session id>",
  "q_index": 0,
  "prev_q_hash": "<sha256 of record q_index - 1, or 64x'0' for 0>",
  "time": "<ISO-8601 UTC>",
  "terminal_mode": "live | captured",
  "trigger": {
    "layer": "vow | guard | ipc | cw_vfs | jail",
    "reason": "<machine-readable refusal code>",
    "call_json": "<canonical JSON of refused P1 request>",
    "context_sha256": "<sha256 of preceding prompt/file context>"
  },
  "artifacts": [
    {
      "relpath": "r.py",
      "size": 248,
      "sha256": "<sha256 of staging file>",
      "blob_ref": "blobs/<sha256>"
    }
  ],
  "kernel_telemetry": {
    "trace_sha256": "<sha256 of raw strace output, or null>",
    "trace_ref": "traces/<q_index>.strace",
    "strace_seccomp_bpf": false
  },
  "pivot_chain": [0, 1]
}
```

*As built (slice 4a):* `monitor.Quarantine`, in the monitor process.
- **What goes in:**
  - P0's own cw_vfs refusals: every file call cw_vfs refused, in the real workdir. `reason` is the
    errno's name (`EXDEV` for a `../` or absolute path outside, `ENOENT` for a missing file), or the
    exception's when there is none. `record_index` names the call's record in the session chain.
  - The Vow and guard refusals the gate decides, reported over IPC (the `quarantine` operation):
    `forbidden:<effects>` for a call the critic refused before it ran, and the verdict for a run the
    guard withheld.
  - P0 accepts only those two layers from the gate, with a reason of at most 128 characters and a
    context hash or none. Anything else is a protocol violation.
- **What is kept:** each record is the schema above, with `call_sha256` and `record_index` added to
  the trigger. `call_json` is kept up to 4096 bytes, and `call_sha256` is over all of it.
  `artifacts`, `kernel_telemetry` and `pivot_chain` are empty for now: nothing fills them yet.
- **Caps:** past 1000 records a session's further refusals are only counted, as `dropped`.
- **Signed:** at every append P0 signs a checkpoint over `(session, q_index, head, terminal_mode,
  dropped)`. `monitor.check_quarantine` checks a stream against it and the monitor's key: chained
  from the first record, in order, none missing. `verify.py check LEDGER --quarantine DIR` runs it
  with the ledger's pinned Monitor key.
- **Where:** `records.jsonl` and `checkpoint.json` under `<dir>/<session>/`. From `guarded_agent`'s
  command line, `<dir>` is `--quarantine DIR`, or next to the ledger (`LEDGER.quarantine`). Without
  either, the stream is kept in the monitor's memory, and every reply that adds a record carries it
  and its checkpoint, as replies carry session records.
- **Refused at startup:** a quarantine directory that overlaps the workdir (P0 will not start), or
  one the confined gate could write (under `/dev`, say).
- **The session stays live:** a refusal is recorded, and the next call runs. The latch is slice 4b.
- **Not yet:** refused syscalls are in the raw trace and in each run's events, not in the stream.

#### P0 enforcement and tripwire invariants

- **Isolated from BoundedDebt:**
  - Refused operations leave `recordedDebt`, `allowance` and `cumProv` untouched. In
    `lean/BoundedDebt.lean` §9, `runWith` keeps the state unchanged on a refused step.
  - The quarantine stream enforces its own hard caps (`max_record_bytes`, `max_blob_bytes`, `q_max`
    entries per session), so spam cannot exhaust disk or pollute the honest session's budget.
- **Telemetry-only syscall denials:**
  - The blocked syscalls (`openat2`, `execveat`, `io_uring_setup`, `socket`, and the rest of
    `confine.py`'s deny list) are in `jail.SYSCALLS`, so they appear in the raw strace blob.
  - Both parsers record each one that failed as a `refused` event: `(call, what it named, errno)`.
    `jail.effects_of` gives it no effect.
  - `--seccomp-bpf` must stay off. With it, the filter's errno outranks strace's trace stop, and the
    refused calls vanish from the trace (verified at `bb926a5`). `tests/test_refused_calls.py` pins
    it.
  - glibc's name-service lookups make refused `socket(AF_UNIX)` calls in ordinary commands
    (`id -un; ls -l` makes six). bwrap's own setup sockets appear in the raw trace before the
    filter is installed. The parsers skip them, as they skip everything before the command starts.
  - So these events are recorded strictly as forensic telemetry, never as refusal or tripwire
    triggers. `jail.parse` and `witness.py` agree on them: `tests/test_witness.py` and
    `tests/test_refused_calls.py` check it.
- **Irreversible live → captured latch (strictly terminal):** on a tripwire event, P0:
  1. closes `real_jail._root_fd` and deletes the `real` space handle;
  2. applies `landlock_restrict_self`, restricting P0 to the quarantine/log directory only;
  3. writes the final `QuarantineRecord` with `terminal_mode = "captured"`, and signs the terminal
     ML-DSA-65 checkpoint over `(session, q_index, head_hash, "captured")`;
  4. refuses all further tool execution and spawns no further jails.
- **Kernel constraint (verified at `bb926a5`):**
  - Once a process is under a Landlock ruleset that restricts the filesystem, the kernel refuses it
    `mount(2)` with EPERM, even as root.
  - bwrap started from such a process fails at its first mount: `bwrap: Failed to make / slave:
    Operation not permitted`.
  - Consequently, P0 never applies Landlock to itself during live mode, and captured mode is strictly
    terminal (no quarantine honeypot).
- **Deferred formalization:** the Lean 4 absorbing-mode latch (`Mode := live | captured`,
  `captured_is_absorbing`, and a finite `qLeft` budget) is deferred to Phase 4, when `BoundedDebt.lean`
  is wired into P0.

## 6. BoundedDebt hook (deferred)

P0 is where the guard of `lean/BoundedDebt.lean` §9 belongs: it holds the state and sees every operation,
so refusing there makes the budget an enforced property instead of a policy. `guard_alone_bound` is the
theorem that check needs: any step function whose accepted transitions pass `GuardOK` keeps recorded debt
within `n + (n + c)·k₀`, whatever operations exist.

This needs a decision first (§8, item 1).

## 7. Phases, for Claude Code

**Phase 0: one cw_vfs, merged into `main`.** Done: #25 (BoundedDebt and its CI step), #28 (cw_vfs),
#29 (the adversarial suite).
- Base: the v2 patch.
- Bring over from the D12 line: `mkdir_confined`; the directories-first clone (exact modes, empty
  directories); dup'd `scandir` descriptors; and no `st_dev` equality in the hop walk, the leaf check,
  the Coq statement or `verify` (`RESOLVE_NO_XDEV` enforces it).
- Add `Sandbox.logical_workdir`.
- Fix the rehearsal regression: mount the scratch copy at the real workdir path
  (`jail._bwrap(workdir, source=copy)`, as `replay._traced` already does), so the trace and the evidence
  agree on paths.
- Give the two `test_evidence` fixtures witnesses.
- Adopt the adversarial suite, and change its two tests that encode the older rules.
- Add `lean/BoundedDebt.lean` and its CI step (it compiles with the pinned Lean 4.14).
- Exit: `pytest -q` green with `DHARMA_REQUIRE_JAIL=1`; `containment_mutants.py` (unprivileged and
  root); `run_demo.py`.

**Phase 1: close F1 in the jail.** Done: #26 and #27.
- **#26:** Landlock and the seccomp deny list, in `confine.py`.
  - Probes for the untraced calls are in `tests/test_containment.py`.
  - The filter is checked call by call against the kernel headers in `tests/test_confine.py`.
  - `repro_openat2.py` became the regression test `tests/test_untraced_reads.py`.
- **#27:** narrow binds, and Unix sockets (F6), with probes for both.
- **`containment_mutants.py`** tests each layer with the other switched off, and catches every mutant.
- **Differences from the plan:**
  - The untraced calls fail with ENOSYS rather than EPERM.
  - There is no compiled launcher: `confine.py` runs as source under the jail's own `python3 -I`.

**Phase 2: P0 and IPC.**
- Move the real operations, jail spawning and snapshots into `monitor.py`; P1 uses the client.
  *Done (slices 2 and 3a):*
  - the monitor process and its client;
  - rehearsal copies in the gate's monitor;
  - the co-signer's snapshots and replays in a monitor of its own.

  The gate's process runs no jail and copies nothing (`tests/test_monitor_process.py`), which is what
  Landlock on it (slice 3b) needs.
- Add the session header, chained records and checkpoints, with the binding checks in `verify.py`.
  *Done, in-process:* `monitor.py` (slice 1).
- Apply Landlock to P1 so it cannot open the workdir. *Done (slice 3b):* `gate_confine.py`.
- Replace every `getattr` dispatch with a table (F4). *Done:* `tools.dispatch`.
- Add the quarantine stream and the terminal capture latch (§5). *Done (slice 4a):* the stream
  (`monitor.Quarantine`). The latch is slice 4b.
- Trace the blocked syscalls as telemetry only, in both parsers, with a test pinning `--seccomp-bpf` off.
  *Done:* `tests/test_refused_calls.py`.
- Exit:
  - a test shows P1 cannot open the workdir (`tests/test_gate_landlock.py`: not directly, through
    `/proc/self/root`, or through a symlink of its own, while every call still runs);
  - every operation appears in a verified chain, and a tampered record fails `verify.py`;
  - a refused call appears in the quarantine stream (`tests/test_quarantine.py`);
  - after a tripwire, P0 can neither open the workdir nor start a jail.

**Phase 3: keys out of P1.**
- Move the co-signers into P2.
- `PR_SET_DUMPABLE=0` in P0 and P2; seccomp in P1 denying `ptrace` and `process_vm_*`; separate uids
  where the platform allows.
- Exit: P1 holds no key material.

**Phase 4: the BoundedDebt guard in P0**, after decision 1, with the absorbing `Mode` latch of §5.

## 8. Open decisions

1. **What is a commit and what is a retraction** for the budget in Dharmapala's terms? Candidates:
   accepted plans versus rollbacks, or Vow and policy changes versus relaxations.
2. **Who owns the ledger file:** P0, or a separate ledger process. *Decided:* P0. It stores the
   entries P1 sends as opaque bytes, size-capped and hash-chained, and never interprets them, so
   owning the ledger does not make it a parser.
3. **Separate uids for P0 and P2**, or one uid with `PR_SET_DUMPABLE=0` and seccomp.
4. **Disclosure.** The repository is public. This document and `repro_openat2.py` describe an unfixed
   bypass, so land Phase 1 with them or before them. *Resolved:* Phase 1 (#26, #27) landed before
   either was published.
5. **Who raises a tripwire.** P0 parses nothing untrusted, but most tripwires are found by parsing:
   - a refused syscall shows only in the trace;
   - Vow and guard refusals are decided in P1.

   P0 can record what P1 reports and act on it, but it cannot check it. A compromised P1 can raise a
   false tripwire, which ends the session (fail closed), or stay silent about a real one. `cw_vfs` and
   IPC refusals are P0's own. The options:
   - accept this, since P1 compromise is Phase 3's concern;
   - give the tripwire decision a parser of its own outside P1, for example in P2.

   *Decided:*
   - **P0 latches only on what an honest P1 cannot produce:** malformed IPC frames, unknown operations
     or arguments at the IPC layer, and P0's own invariant failures.
   - **Everything else goes to the quarantine stream, and the session stays live:** `cw_vfs` refusals
     (a missing file, a `../` path, an absolute path outside the workdir all come back as these),
     BoundedDebt budget refusals, and refused syscalls.
   - **P1 reports trace and Vow tripwires.** A false one ends the session, which fails closed. A
     silent one is caught after the fact by P2 re-reading P0's signed raw traces (Phase 3): P2 catches
     the lie, but does not prevent the action.
