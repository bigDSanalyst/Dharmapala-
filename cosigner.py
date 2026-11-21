"""The co-signers as a process of their own (P2): docs/monitor-boundary.md,
section 3, P2; Phase 3, slice 1.

The co-signer checks the guard: it re-derives a run's effects from the run
record with its own parser, replays the run in a monitor process of its own,
checks the certificate with coqc, and signs what it vouches for. The
trajectory co-signer signs the Vow's trajectory verdicts. Their keys are what
every attestation in the ledger rests on, so they belong neither in the
gate's process (P1), which parses everything the model and the tools send
back, nor in the monitor's (P0). Here they are in a process of their own,
started by the gate the way it starts its monitor (monitor.py), and before it
confines itself:
- on a socketpair, with length-prefixed canonical JSON frames;
- undumpable (PR_SET_DUMPABLE 0), killed with its parent (PR_SET_PDEATHSIG);
- serving no peer but its parent (SO_PEERCRED);
- holding its replay monitor (P0') as a child of its own, which the gate
  never sees.

The gate holds the two public keys, from the process's hello, and handles on
it (RemoteCoSigner, RemoteTrajectoryCoSigner). The private keys never leave
this process.

What crosses is values, never code. The co-signer runs the engine it was
built with against the binary it hashes itself; it rebuilds each attestation,
decision, action and trajectory clause from its fields; and a snapshot it
takes stays with it, the gate holding only a handle. A request that is not
exactly a known operation ends the process, and with it every attestation:
the gate's calls are then not checked (ConfigError), and none is signed.
"""
import dataclasses
import json
import os
import socket
import struct
import subprocess
import sys

import monitor as monitor_mod
from monitor import canon, recv_frame, send_frame

MAX_REQUEST = 256 << 20      # a run's evidence carries its raw traces, as the monitor's answers do
MAX_RESPONSE = 1 << 20
PROTOCOL_EXIT = 3
OPS = {"snapshot": (), "release": ("handle",),
       "cosign": ("proposal", "inputs", "decision", "evidence", "snapshot"),
       "traj_cosign": ("clauses", "prior_state", "action", "verdict")}

class CoSignerGone(RuntimeError):
    """The co-signer process is not there to answer: nothing more is signed."""


# --- values across the boundary ----------------------------------------------------

def action_to(action):
    return {"id": action.id, "verb": action.verb, "domain": action.domain, "effects": sorted(action.effects())}

def action_from(d):
    from vow import Action
    a = Action(id=_str(d["id"]), verb=_str(d["verb"]), domain=_str(d["domain"]))
    a._observed_effects = {_str(e) for e in _list(d["effects"])}
    return a

def clause_to(c):
    return {"name": c.name, "pattern": c.pattern.value, "subject": c.subject, "anchor": c.anchor}

def clause_from(d):
    from trajectory import Pattern, TrajectoryClause
    return TrajectoryClause(_str(d["name"]), Pattern(d["pattern"]), _str(d["subject"]),
                            None if d["anchor"] is None else _str(d["anchor"]))

def decision_from(d):
    from decision import Decision
    return Decision(**dict(d, effects=tuple(_list(d["effects"])), forbidden=tuple(_list(d["forbidden"]))))

def attestation_from(d):
    from to_coq_witness import Attestation
    return Attestation(**d)

def trajectory_attestation_from(d):
    from trajectory import TrajectoryAttestation
    return TrajectoryAttestation(**dict(d, prior_state=tuple(_list(d["prior_state"]))))

def _str(v):
    if not isinstance(v, str): raise ValueError(f"not a string: {v!r}")
    return v

def _list(v):
    if not isinstance(v, list): raise ValueError(f"not a list: {v!r}")
    return v

def _dict_or_none(v):
    if v is not None and not isinstance(v, dict): raise ValueError(f"not an object: {v!r}")
    return v


# --- the process -------------------------------------------------------------------

def check_request(data, seq):
    """The request in `data`, if it is the next one and well formed; else ValueError."""
    try: obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError): raise ValueError("not JSON") from None
    if not isinstance(obj, dict) or canon(obj).encode() != data: raise ValueError("not canonical JSON")
    if set(obj) != {"v", "seq", "op", "args"} or obj["v"] != 1: raise ValueError("not a v1 request")
    if type(obj["seq"]) is not int or obj["seq"] != seq: raise ValueError(f"out of sequence (expected {seq})")
    if obj["op"] not in OPS or not isinstance(obj["args"], dict) or set(obj["args"]) != set(OPS[obj["op"]]):
        raise ValueError(f"not a call to a known operation: {str(obj['op'])[:40]!r}")
    return obj

def serve(fd, workdir, policy_json, monitor_scheme, monitor_public):
    monitor_mod._harden()
    parent = os.getppid()
    sock = socket.socket(fileno=fd)
    pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    if (pid, uid) != (parent, os.getuid()) or parent == 1:
        print(f"cosigner: refusing peer pid {pid} uid {uid}", file=sys.stderr); return 1
    import policy as policy_mod
    import replay
    from signing import MLDSASigner, PublicVerifier
    from to_coq_witness import ConfigError, CoSigner, DecisionError, RefusedToSign
    from trajectory import TrajectoryCoSigner
    from guarded_agent import _engine        # the engine the gate's guard proposes with, and its binary
    binary = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guarded_agent.py")
    try: s_co, s_tr = MLDSASigner.generate("CoSigner"), MLDSASigner.generate("Trajectory")
    except ImportError:
        send_frame(sock, {"v": 1, "refused": "no ML-DSA-65 (pip install dilithium-py)"}); return 1
    try: own = monitor_mod.RemoteMonitor(workdir)    # replays run in a monitor of its own (P0')
    except monitor_mod.MonitorGone as e:
        send_frame(sock, {"v": 1, "refused": f"its replay monitor would not start: {e}"}); return 1
    co = CoSigner(s_co, reexecute=True, policy=policy_mod.of(json.loads(policy_json)),
                  monitor=PublicVerifier("Monitor", monitor_scheme, bytes.fromhex(monitor_public)),
                  workdir=workdir, replay_monitor=own)
    tr = TrajectoryCoSigner(s_tr)
    send_frame(sock, {"v": 1, "hello": {
        "cosigner": {"id": s_co.id, "scheme": s_co.scheme, "public": s_co.public_bytes().hex()},
        "trajectory": {"id": s_tr.id, "scheme": s_tr.scheme, "public": s_tr.public_bytes().hex()},
        "replay_monitor_pid": own.pid}})
    refusals = {"RefusedToSign": RefusedToSign, "ConfigError": ConfigError, "DecisionError": DecisionError}
    held, made, seq = {}, 0, 0
    try:
        while True:
            try: data = recv_frame(sock, MAX_REQUEST)
            except OSError: return 0                                # the gate hung up
            except ValueError as e:
                print(f"cosigner: protocol violation: {e}", file=sys.stderr); return PROTOCOL_EXIT
            if data is None: return 0
            try:
                req = check_request(data, seq)
                op, args = req["op"], req["args"]
                if op == "release": _str(args["handle"])
                elif op == "cosign":
                    proposal = attestation_from(args["proposal"])
                    inputs = args["inputs"]
                    if not isinstance(inputs, dict): raise ValueError("inputs are not an object")
                    decision = None if args["decision"] is None else decision_from(args["decision"])
                    evidence = _dict_or_none(args["evidence"])
                    snapshot = None if args["snapshot"] is None else _str(args["snapshot"])
                elif op == "traj_cosign":
                    clauses = [clause_from(c) for c in _list(args["clauses"])]
                    prior_state = tuple(_list(args["prior_state"]))
                    if not all(type(s) is int for s in prior_state): raise ValueError("a state is not an integer")
                    action, verdict = action_from(args["action"]), _str(args["verdict"])
            except (ValueError, TypeError, KeyError) as e:
                print(f"cosigner: protocol violation: {e}", file=sys.stderr); return PROTOCOL_EXIT
            reply = {"v": 1, "seq": seq, "ok": True}
            if op == "snapshot":
                try:
                    snap = co.snapshot(workdir); made += 1
                    reply["handle"] = f"snap{made}"; held[reply["handle"]] = snap
                except replay.Unreplayable as e:
                    reply.update(handle=None, error=str(e))
                except monitor_mod.MonitorGone as e:          # its replay monitor: then nothing is replayed
                    reply.update(handle=None, error=f"its replay monitor is gone: {e}")
            elif op == "release":
                co.release(held.pop(args["handle"], None))
            elif op == "cosign":
                try:
                    signed = co.cosign(proposal, "", inputs, binary, _engine, decision=decision, evidence=evidence,
                                       snapshot=held.get(snapshot))     # a handle it never gave: no snapshot
                    reply["attestation"] = dataclasses.asdict(signed)
                except tuple(refusals.values()) as e:
                    reply.update(refused=type(e).__name__, message=str(e))
                reply["notes"] = list(co.notes)
            elif op == "traj_cosign":
                accepted, result = tr.cosign(clauses, prior_state, action, verdict)
                reply["accepted"] = accepted
                if accepted: reply["attestation"] = dataclasses.asdict(result)
                else: reply["message"] = str(result)
            try: send_frame(sock, reply)
            except OSError: return 0
            seq += 1
    finally:
        for snap in held.values(): co.release(snap)
        own.close()
        sock.close()


# --- the gate's side ---------------------------------------------------------------

class CoSignerProcess:
    """The gate's handle on the co-signer process for `workdir`: both
    co-signers' public keys, never their signing keys."""
    def __init__(self, workdir, policy, monitor_verifier, timeout=600):
        import policy as policy_mod
        self.workdir = os.path.realpath(workdir)
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        here = os.path.dirname(os.path.abspath(__file__))
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-E", "-s", os.path.join(here, "cosigner.py"), "serve", str(theirs.fileno()),
                 self.workdir, canon(policy_mod.of(policy).to_dict()), monitor_verifier.scheme,
                 monitor_verifier._pub.hex()],
                pass_fds=[theirs.fileno()], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, cwd=here)
        finally:
            theirs.close()
        self._sock, self._seq, self._gone = ours, 0, None
        self._sock.settimeout(timeout)
        hello = self._recv()
        if "hello" not in hello:
            self.close(); raise CoSignerGone(f"the co-signer refused to start: {hello.get('refused', hello)}")
        h = hello["hello"]
        self.replay_monitor_pid = h["replay_monitor_pid"]
        self.cosigner = RemoteCoSigner(self, h["cosigner"])
        self.trajectory = RemoteTrajectoryCoSigner(self, h["trajectory"])
    @property
    def pid(self): return self._proc.pid

    def gone(self):
        """Why the co-signer process can sign nothing more, or None while it can."""
        if self._gone is None and self._proc.poll() is not None:
            self._gone = f"the co-signer process is gone (exit {self._proc.returncode})"
        return self._gone

    def _recv(self):
        try: data = recv_frame(self._sock, MAX_RESPONSE)
        except (OSError, ValueError) as e: raise CoSignerGone(f"the co-signer stopped answering: {e}") from None
        if data is None: raise CoSignerGone("the co-signer process is gone")
        try: obj = json.loads(data)
        except ValueError: obj = None
        if not isinstance(obj, dict): raise CoSignerGone("the co-signer answered with something not a JSON object")
        return obj

    def call(self, op, **args):
        if self._gone: raise CoSignerGone(self._gone)
        try:
            try: send_frame(self._sock, {"v": 1, "seq": self._seq, "op": op, "args": args})
            except OSError as e: raise CoSignerGone(f"the co-signer process is gone: {e}") from None
            resp = self._recv()
            if resp.get("seq") != self._seq or not resp.get("ok"):
                raise CoSignerGone(f"the co-signer answered out of turn: {str(resp)[:120]}")
        except CoSignerGone as e:
            self._gone = str(e); raise          # for good: it is not asked again
        self._seq += 1
        return resp

    def close(self):
        try: self._sock.close()
        except OSError: pass
        try: self._proc.wait(timeout=30)
        except subprocess.TimeoutExpired: self._proc.kill(); self._proc.wait()
    def __del__(self):
        try: self.close()
        except Exception: pass

def _verifier(hello):
    from signing import PublicVerifier
    return PublicVerifier(hello["id"], hello["scheme"], bytes.fromhex(hello["public"]))

class RemoteCoSigner:
    """to_coq_witness.CoSigner's interface, answered by the co-signer process."""
    reexecute = True
    def __init__(self, proc, hello):
        self._proc, self.id, self.verifier, self.notes = proc, hello["id"], _verifier(hello), []
    @property
    def gone(self):
        """Why nothing more can be signed, or None: the gate runs nothing more once it is gone."""
        return self._proc.gone()
    def snapshot(self, workdir):
        """A handle on a copy of the workdir the co-signer took and keeps."""
        import replay
        if os.path.realpath(workdir) != self._proc.workdir:
            raise ValueError(f"this co-signer serves {self._proc.workdir}, not {workdir}")
        try: r = self._proc.call("snapshot")
        except CoSignerGone as e: raise replay.Unreplayable(str(e)) from None
        if r.get("handle") is None: raise replay.Unreplayable(r.get("error", "no snapshot"))
        return r["handle"]
    def release(self, handle):
        if handle is None: return
        try: self._proc.call("release", handle=handle)
        except CoSignerGone: pass
    def cosign(self, proposal, cert_path, inputs, binary_path, re_run_fn, decision=None, evidence=None,
               snapshot=None):
        """cert_path, binary_path and re_run_fn are the gate's: the co-signer
        process hashes its own binary and runs its own engine."""
        from to_coq_witness import ConfigError, DecisionError, RefusedToSign
        try:
            r = self._proc.call("cosign", proposal=dataclasses.asdict(proposal), inputs=inputs,
                                decision=None if decision is None else dataclasses.asdict(decision),
                                evidence=evidence, snapshot=snapshot)
        except CoSignerGone as e:
            self.notes = ["co-signer: GONE"]
            raise ConfigError(f"not checked: {e}") from None
        self.notes = list(r.get("notes", []))
        if "refused" in r:
            kind = {"RefusedToSign": RefusedToSign, "ConfigError": ConfigError, "DecisionError": DecisionError}
            raise kind[r["refused"]](r["message"])
        signed = attestation_from(r["attestation"])
        if not self.verifier.verify(signed.payload(), bytes.fromhex(signed.signature)):
            raise ConfigError("not checked: the co-signer's attestation does not verify under its key")
        if dataclasses.replace(signed, certificate_status=proposal.certificate_status,
                               signature=proposal.signature) != proposal:
            raise ConfigError("not checked: the co-signer's attestation is not for the proposal it was sent")
        return signed

class RemoteTrajectoryCoSigner:
    """trajectory.TrajectoryCoSigner's interface, answered by the co-signer process."""
    def __init__(self, proc, hello):
        self._proc, self.id, self.verifier = proc, hello["id"], _verifier(hello)
    def cosign(self, clauses, prior_state, action, guard_verdict):
        try:
            r = self._proc.call("traj_cosign", clauses=[clause_to(c) for c in clauses],
                                prior_state=list(prior_state), action=action_to(action), verdict=guard_verdict)
        except CoSignerGone as e:
            return False, str(e)
        if not r["accepted"]: return False, r["message"]
        signed = trajectory_attestation_from(r["attestation"])
        if not self.verifier.verify(signed.payload(), bytes.fromhex(signed.signature)):
            return False, "the trajectory co-signer's attestation does not verify under its key"
        if (signed.signer_id, signed.action_digest, signed.verdict) != (self.id, action.canonical_digest(),
                                                                         guard_verdict):
            return False, "the trajectory co-signer's attestation is not for the action it was sent"
        return True, signed

def start(workdir, policy, monitor_verifier):
    """The co-signers in a process of their own, given ML-DSA-65; None without
    it (then they stay in the gate's process, under HMAC keys)."""
    try:
        import dilithium_py.ml_dsa  # noqa: F401
    except ImportError:
        return None
    return CoSignerProcess(workdir, policy, monitor_verifier)

if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "serve":
        sys.exit(serve(int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]))
    print("usage: cosigner.py serve FD WORKDIR POLICY_JSON MONITOR_SCHEME MONITOR_PUBLIC "
          "(started by CoSignerProcess)", file=sys.stderr)
    sys.exit(2)
