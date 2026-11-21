"""Unix sockets: out of the jail's reach, and seen when one is reached anyway.

A host daemon's socket file (an SSH or GPG agent, Docker's) is a door out of
the jail that the network namespace does not close. Two layers keep a command
from it: the jail mounts only the system directories, so the socket's
directory is not there, and confine.py's filter refuses socket(AF_UNIX, ...).
The containment probes (tests/test_containment.py) check each layer alone.

Should a command reach one all the same, the trace now shows it: both parsers
report a connect to a socket file as an event, and the Vow judges it as a write
to that path. Before, both skipped every AF_UNIX connect as "not the network"."""
import os
import pathlib
import shutil
import socket
import tempfile
import threading

import pytest

import tests.support  # noqa: F401
import guarded_agent as ga
import jail
import witness
from tests.test_guarded_agent import Scripted, call, results, text, turn
from tests.test_jail import needs_jail

CMD = "python3 c.py"
EXEC = 'execve("/usr/bin/sh", ["sh", "-c", "python3 c.py"], 0x7ffd /* 3 vars */) = 0'


def trace(*lines):
    return {101: "\n".join([EXEC, *lines]) + "\n"}


CONNECTS = [
    'connect(3<socket:[11]>, {sa_family=AF_UNIX, sun_path="/run/docker.sock"}, 19) = 0',
    'connect(4<socket:[12]>, {sa_family=AF_UNIX, sun_path="agent.sock"}, 13) = -1 ENOENT (No such file or directory)',
    'connect(5<socket:[13]>, {sa_family=AF_UNIX, sun_path=@"dharma-abstract"}, 18) = 0',
    'connect(6<socket:[14]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ENETUNREACH',
]


def test_both_parsers_report_a_connect_to_a_socket_file():
    t = trace(*CONNECTS)
    want = [("unix", os.path.realpath("/run/docker.sock"), True),
            ("unix", "agent.sock", False),
            ("connect", "10.0.0.1", False)]
    assert jail.parse(t, CMD) == want
    assert witness.parse(t, CMD) == want


def test_an_abstract_socket_is_the_jails_own_and_not_reported():
    t = trace(CONNECTS[2])
    assert jail.parse(t, CMD) == [] and witness.parse(t, CMD) == []


@pytest.mark.parametrize("path, effects", [
    ("/run/docker.sock", {"exec", "write", "write_outside_workdir"}),
    ("/work/app.sock", {"exec", "write"}),
    ("agent.sock", {"exec", "write", "write_outside_workdir"}),   # where it resolves is not in the trace
    ("/run/nscd/socket", {"exec"}),                               # libc's lookup, as LOADER_READS
])
def test_a_socket_connect_is_judged_as_a_write_to_its_path(path, effects):
    assert jail.effects_of([("unix", path, True)], "/work") == effects


def test_an_attempt_counts_like_a_success():
    """As with every other event: trying to reach the socket is the effect."""
    assert jail.effects_of([("unix", "/run/docker.sock", False)], "/work") == \
        {"exec", "write", "write_outside_workdir"}


SERVER_AND_CLIENT = """import os, socket
p = os.path.abspath("app.sock")
srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)
c = socket.socket(socket.AF_UNIX); c.connect(p); c.send(b"x")
print("connected", p)
"""


@needs_jail
def test_a_connect_the_filter_did_not_stop_is_seen(tmp_path, monkeypatch):
    """With confine.py switched off, a socket in the workdir can be made and
    connected to, and the trace shows the connect: the observation does not
    depend on the filter."""
    w = tmp_path / "w"; w.mkdir(); (w / "c.py").write_text(SERVER_AND_CLIENT)
    monkeypatch.setattr(jail, "_confine", lambda w: [])
    r = jail.run(CMD, str(w))
    path = os.path.realpath(w / "app.sock")
    assert "connected" in r.stdout, r.stderr
    assert ("unix", path, True) in r.events
    assert ("unix", path, True) in witness.events_for({"trace": r.trace}, CMD)
    assert jail.effects_of(r.events, str(w)) >= {"write"}


@needs_jail
def test_the_filter_stops_the_socket_before_any_connect(tmp_path):
    w = tmp_path / "w"; w.mkdir(); (w / "c.py").write_text(SERVER_AND_CLIENT)
    r = jail.run(CMD, str(w))
    assert "connected" not in r.stdout and "PermissionError" in r.stderr
    assert not [e for e in r.events if e[0] == "unix"]


@pytest.fixture
def host_socket():
    """A listener outside /tmp, standing in for a host daemon's socket."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="dharma-sock-", dir="/var/tmp"))
    path = str(d / "agent.sock")
    srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(4); srv.settimeout(0.2)
    reached, stop = [], threading.Event()
    def accept():
        while not stop.is_set():
            try: conn, _ = srv.accept()
            except (socket.timeout, OSError): continue
            reached.append(conn.recv(64)); conn.sendall(b"DHARMA-DAEMON-REPLY"); conn.close()
    t = threading.Thread(target=accept, daemon=True); t.start()
    try:
        yield path, reached
    finally:
        stop.set(); t.join(2); srv.close(); shutil.rmtree(d, ignore_errors=True)


@needs_jail
def test_a_host_daemons_socket_is_not_reached_through_the_gate(tmp_path, host_socket):
    """End to end: the rehearsal, the real run and the co-signer's replay all
    run the command in the jail, and none of them reaches the socket."""
    path, reached = host_socket
    script = ("import socket\ns = socket.socket(socket.AF_UNIX)\n"
              f"s.connect({path!r}); s.send(b'hello'); print(s.recv(64))\n")
    gate, _ = ga.setup(tmp_path / "work")
    client = Scripted(turn(call(1, "file_write", path="c.py", content=script)),
                      turn(call(2, "shell", cmd="python3 c.py")),
                      turn(text("done"), stop="end_turn"))
    ga.GuardedAgent(client, gate).run("task")
    [r] = results(client, 2)
    assert not reached, "a command in the jail reached a socket on the host"
    assert "DHARMA-DAEMON-REPLY" not in r["content"]
