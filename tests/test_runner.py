"""End-to-end runner tests against the plain-UDP echo adapter (real processes, real sockets)."""

from __future__ import annotations

import dataclasses
import json
import re
import select
import socket
import threading
import time
from pathlib import Path

import pytest
from echo_adapter import ECHO_VERSION, child_pids, install, pid_alive

from dtls_interop import implementations, runner, scenarios
from dtls_interop.implementations import BOTH_ROLES
from dtls_interop.proxy import FORWARD, Rule, UdpProxy
from dtls_interop.results import (
    RESULT_FILE,
    SCHEMA_VERSION,
    Outcome,
    PathRecord,
    RunLayout,
    SchemaError,
    read_result,
    read_run,
)
from dtls_interop.scenarios import ClientOptions, Impairment, PathConditions

S01 = scenarios.get("S01")
# Generous deadlines for cases that should finish; they bound a failure, they are not sleeps.
OK_LIMITS = {"ready_timeout": 10.0, "case_timeout": 20.0, "server_grace": 5.0}


@pytest.fixture(autouse=True)
def no_leftover_children():
    before = child_pids()
    yield
    assert child_pids() <= before, "runner left child processes behind"


@pytest.fixture
def layout(tmp_path: Path) -> RunLayout:
    return RunLayout.new(tmp_path / "results")


def run(tmp_path, layout, test_pki, client_flags=(), server_flags=(), scenario=S01, **kw):
    client = install(tmp_path, "echo-client", *client_flags)
    server = install(tmp_path, "echo-server", *server_flags)
    limits = OK_LIMITS | kw
    return runner.run_case(scenario, client, server, layout=layout, pki=test_pki, **limits)


def case_dir(layout: RunLayout, scenario=S01) -> Path:
    return layout.case_dir(scenario.id, "echo-client", "echo-server")


def test_pass_records_everything(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki)

    assert result.outcome is Outcome.PASS, result.reason
    assert result.reason is None
    assert result.schema_version == SCHEMA_VERSION
    assert result.scenario == "S01"
    assert result.run_id == layout.run_id
    for side, name in ((result.client, "echo-client"), (result.server, "echo-server")):
        assert side.implementation == name
        assert side.implementation_version == ECHO_VERSION
        assert side.started and side.exit_code == 0 and not side.killed
        assert side.result == {
            "event": "result",
            "ok": True,
            "version": None,
            "group": None,
            "hrr": None,
            "hrr_cookie": None,
            "hrr_group": None,
            "resumed": False,
            "error": None,
        }
        assert side.variant == "default"
        assert side.duration_s is not None and side.duration_s >= 0
    assert result.server.command[1:] == [
        "--role=server",
        "--variant=default",
        "--transport=dtls",
        "--resume=off",
        "--host=127.0.0.1",
        "--port=0",
        "--groups=X25519",
        "--mtu=1500",
        f"--ca={test_pki.ca_cert}",
        "--validate=off",
        f"--cert={test_pki.server_cert}",
        f"--key={test_pki.server_key}",
    ]
    ready = json.loads((case_dir(layout) / "server.stdout").read_text().splitlines()[0])
    client_port = next(a for a in result.client.command if a.startswith("--port="))
    # By default the client talks to the proxy, which forwards to the server's port.
    assert client_port != f"--port={ready['port']}"
    assert result.client.command[1:] == [
        "--role=client",
        "--variant=default",
        "--transport=dtls",
        "--resume=off",
        "--host=127.0.0.1",
        client_port,
        "--groups=X25519",
        "--mtu=1500",
        f"--ca={test_pki.ca_cert}",
        "--key-share=X25519",
    ]
    assert result.path == PathRecord(
        proxied=True, pmtu=1500, impairments=[], split_ch1=None, actions={}
    )
    assert result.trace == "trace.jsonl"
    trace = [
        json.loads(line) for line in (case_dir(layout) / result.trace).read_text().splitlines()
    ]
    assert [(d["direction"], bytes.fromhex(d["payload"]), d["action"]) for d in trace] == [
        ("c2s", b"ping", "forwarded"),
        ("s2c", b"pong", "forwarded"),
    ]
    # Plain UDP carries no ClientHello.
    assert result.ch1_size is None and result.ch2_fragments is None
    assert result.cookie_echoed is None

    d = case_dir(layout)
    assert d.parent.parent.parent.name == layout.started.strftime("%Y-%m-%d")
    assert '"event": "ready"' in (d / result.server.stdout_log).read_text()
    assert re.search(r"pid=\d+", (d / result.client.stderr_log).read_text())


def test_direct_path_without_proxy(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, path_factory=None)

    assert result.outcome is Outcome.PASS, result.reason
    ready = json.loads((case_dir(layout) / "server.stdout").read_text().splitlines()[0])
    assert f"--port={ready['port']}" in result.client.command
    assert result.path == PathRecord(
        proxied=False, pmtu=1500, impairments=[], split_ch1=None, actions={}
    )
    assert result.trace is None
    assert not (case_dir(layout) / "trace.jsonl").exists()


def test_result_json_round_trip(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki)
    path = case_dir(layout) / RESULT_FILE

    assert read_result(path) == result
    assert read_run(layout.directory) == [result]
    data = json.loads(path.read_text())
    assert data["outcome"] == "pass"
    assert data["client"]["stdout_log"] == "client.stdout"


def test_read_rejects_other_schema_version(tmp_path, layout, test_pki):
    run(tmp_path, layout, test_pki)
    path = case_dir(layout) / RESULT_FILE
    data = json.loads(path.read_text())

    data["schema_version"] = SCHEMA_VERSION + 1
    path.write_text(json.dumps(data))
    with pytest.raises(SchemaError, match="schema_version"):
        read_result(path)

    data["schema_version"] = SCHEMA_VERSION
    data["client"]["surprise"] = 1
    path.write_text(json.dumps(data))
    with pytest.raises(SchemaError, match="unknown keys"):
        read_result(path)

    del data["client"]["surprise"]
    data["outcome"] = "maybe"
    path.write_text(json.dumps(data))
    with pytest.raises(SchemaError, match="outcome"):
        read_result(path)


def test_server_unsupported(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=exit2"])

    assert result.outcome is Outcome.UNSUPPORTED
    assert "not supported" in result.reason
    assert result.server.exit_code == 2
    assert not result.client.started
    assert result.client.stdout_log is None


def test_client_unsupported_stops_server_at_once(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=exit2"])

    assert result.outcome is Outcome.UNSUPPORTED
    assert result.client.exit_code == 2
    # Exit 2 decides the outcome, so the waiting server is killed without the grace period.
    assert result.server.killed and result.server.exit_code is None
    assert result.duration_s < OK_LIMITS["server_grace"] / 2


def test_client_usage_error_stops_server_at_once(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--bogus=1"])

    assert result.outcome is Outcome.ERROR
    assert result.client.exit_code == 64
    assert result.server.killed
    assert result.duration_s < OK_LIMITS["server_grace"] / 2


def test_server_unsupported_mid_handshake_stops_client_at_once(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=exit2-on-ping"])

    assert result.outcome is Outcome.UNSUPPORTED
    assert result.reason == "server: unsupported, found out during the handshake"
    assert result.server.exit_code == 2
    # The client still waits for its pong; the runner kills it instead of waiting for it.
    assert result.client.killed and result.client.exit_code is None
    assert result.duration_s < OK_LIMITS["server_grace"] / 2


def test_client_failure_still_waits_for_the_server(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=fail"])

    assert result.outcome is Outcome.FAIL
    # The server answered the ping and exited by itself within the grace period.
    assert result.server.exit_code == 0 and not result.server.killed


def test_client_hang_times_out(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=hang"], case_timeout=2.0)

    assert result.outcome is Outcome.TIMEOUT
    assert result.client.killed and result.client.exit_code is None
    assert result.client.result is None
    assert result.duration_s < 2.0 + OK_LIMITS["server_grace"]


def test_server_hang_times_out(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=hang"], case_timeout=2.0)

    assert result.outcome is Outcome.TIMEOUT
    assert result.server.killed and result.client.killed


def test_server_never_ready(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=never-ready"], ready_timeout=1)

    assert result.outcome is Outcome.ERROR
    assert result.reason == "server not ready within 1s"
    assert result.server.killed
    assert not result.client.started


def test_garbage_stdout_is_error(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=garbage"])

    assert result.outcome is Outcome.ERROR
    assert "server: non-JSON stdout line 'this is not JSON'" in result.reason
    assert result.client.exit_code == 0


def test_malformed_result_line_is_error(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=bad-result"])

    assert result.outcome is Outcome.ERROR
    assert result.reason == "client: result line lacks 'version'"
    assert result.client.result == {"event": "result", "ok": True}


def test_client_failure_is_fail(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=fail"])

    assert result.outcome is Outcome.FAIL
    assert result.reason == "client: simulated handshake failure"
    assert result.client.exit_code == 1


def test_server_crash_is_fail(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=crash"], case_timeout=2.0)

    assert result.outcome is Outcome.FAIL
    assert result.reason == "server crashed (SIGKILL)"
    assert result.server.exit_code == -9


def test_reported_group_mismatch_is_fail(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=['--report=group="X25519MLKEM768"'])

    assert result.outcome is Outcome.FAIL
    assert result.reason == "server reported group='X25519MLKEM768', expected 'X25519'"


def test_process_groups_are_killed(tmp_path, layout, test_pki):
    flags = ["--behave=hang", "--spawn-child"]
    result = run(tmp_path, layout, test_pki, client_flags=flags, server_flags=flags, case_timeout=2)

    assert result.outcome is Outcome.TIMEOUT
    d = case_dir(layout)
    pids = [
        int(m)
        for log in ("client.stderr", "server.stderr")
        for m in re.findall(r"pid=(\d+)", (d / log).read_text())
    ]
    assert len(pids) == 4
    # SIGKILL delivery is asynchronous; poll with a deadline.
    deadline = time.monotonic() + 10
    while any(pid_alive(p) for p in pids) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not [p for p in pids if pid_alive(p)]


def test_adapter_not_executable(tmp_path, layout, test_pki):
    client = install(tmp_path, "echo-client")
    server = install(tmp_path, "echo-server")
    server.adapter.chmod(0o644)

    result = runner.run_case(S01, client, server, layout=layout, pki=test_pki, **OK_LIMITS)

    assert result.outcome is Outcome.ERROR
    assert result.reason.startswith("cannot start adapter")


@pytest.mark.parametrize(
    ("scenario_id", "reason"),
    [
        ("S08", "path impairments not available"),
        ("S09", "path impairments not available"),
        ("S03+split", "CH1 split needs the proxy"),
    ],
)
def test_unrunnable_scenarios_are_errors(tmp_path, layout, test_pki, scenario_id, reason):
    scenario = scenarios.get(scenario_id)
    result = run(tmp_path, layout, test_pki, scenario=scenario, path_factory=None)

    assert result.outcome is Outcome.ERROR
    assert result.reason == reason
    assert not result.client.started and not result.server.started
    assert read_result(case_dir(layout, scenario) / RESULT_FILE) == result


def test_resumption_runs_two_connections(tmp_path, layout, test_pki):
    s10 = scenarios.get("S10")
    result = run(tmp_path, layout, test_pki, scenario=s10)

    assert result.outcome is Outcome.PASS, result.reason
    assert "--resume=ticket" in result.client.command
    assert "--resume=ticket" in result.server.command
    # The echo server answers one ping per connection, so a pass means both connections ran.
    assert result.client.result["resumed"] is True
    assert result.server.result["resumed"] is True


def test_resumption_not_reported_is_fail(tmp_path, layout, test_pki):
    s10 = scenarios.get("S10")
    result = run(tmp_path, layout, test_pki, scenario=s10, server_flags=["--report=resumed=false"])

    assert result.outcome is Outcome.FAIL
    assert result.reason == "server reported resumed=False, expected True"


def test_resumption_failure_names_the_connection(tmp_path, layout, test_pki):
    s10 = scenarios.get("S10")
    result = run(tmp_path, layout, test_pki, scenario=s10, client_flags=["--behave=fail"])

    assert result.outcome is Outcome.FAIL
    assert result.reason == "client: connection 2: simulated handshake failure"


def tls_trace(layout: RunLayout, scenario) -> list[dict]:
    text = (case_dir(layout, scenario) / "trace.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def test_tls_runs_over_tcp_through_the_tcp_proxy(tmp_path, layout, test_pki):
    t01 = scenarios.get("T01")
    result = run(tmp_path, layout, test_pki, scenario=t01)

    assert result.outcome is Outcome.PASS, result.reason
    for side in (result.client, result.server):
        assert "--transport=tls" in side.command and "--mtu=default" in side.command
    assert result.path.proxied is True
    assert result.trace == "trace.jsonl"
    # No TLS hellos in a plain ping/pong stream: nothing to say about the cookie.
    assert result.cookie_echoed is None
    trace = tls_trace(layout, t01)
    c2s = b"".join(bytes.fromhex(s["payload"]) for s in trace if s["direction"] == "c2s")
    s2c = b"".join(bytes.fromhex(s["payload"]) for s in trace if s["direction"] == "s2c")
    assert (c2s, s2c) == (b"ping", b"pong")
    assert {s["flow"] for s in trace} == {0}


@pytest.mark.parametrize(
    ("hello", "outcome", "echoed"),
    [("echo", Outcome.PASS, True), ("drop", Outcome.FAIL, False), ("alter", Outcome.FAIL, False)],
)
def test_tls_cookie_echo_is_read_from_the_trace(tmp_path, layout, test_pki, hello, outcome, echoed):
    t01 = scenarios.get("T01")
    flags = [f"--tls-hello={hello}"]
    result = run(tmp_path, layout, test_pki, scenario=t01, client_flags=flags, server_flags=flags)

    assert result.outcome is outcome, result.reason
    assert result.cookie_echoed is echoed
    if outcome is Outcome.FAIL:
        assert result.reason == "trace: the client did not echo the HRR cookie in CH2"
    assert read_result(case_dir(layout, t01) / RESULT_FILE) == result


def test_tls_resumption_uses_a_flow_per_connection(tmp_path, layout, test_pki):
    t01 = scenarios.get("T01")
    scenario = dataclasses.replace(
        t01, resumption=True, expected=dataclasses.replace(t01.expected, resumed=True)
    )
    flags = ["--tls-hello=echo"]
    result = run(
        tmp_path, layout, test_pki, scenario=scenario, client_flags=flags, server_flags=flags
    )

    assert result.outcome is Outcome.PASS, result.reason
    assert result.cookie_echoed is True
    assert {s["flow"] for s in tls_trace(layout, scenario)} == {0, 1}


@pytest.mark.parametrize("role", ["client", "server"])
def test_undeclared_transport_is_unsupported_without_starting(tmp_path, layout, test_pki, role):
    both = "dtls\ntls\n"
    client = install(tmp_path, "echo-client", transports="dtls\n" if role == "client" else both)
    server = install(tmp_path, "echo-server", transports=None if role == "server" else both)
    t01 = scenarios.get("T01")

    result = runner.run_case(t01, client, server, layout=layout, pki=test_pki, **OK_LIMITS)

    assert result.outcome is Outcome.UNSUPPORTED
    name = f"echo-{role}"
    assert result.reason == f"{role}: {name} does not declare the tls transport (declares dtls)"
    assert not result.client.started and not result.server.started


def test_tls_only_implementation_skips_dtls(tmp_path, layout, test_pki):
    client = install(tmp_path, "echo-client", "--implements=tls", transports="tls\n")
    server = install(tmp_path, "echo-server")

    dtls = runner.run_case(S01, client, server, layout=layout, pki=test_pki, **OK_LIMITS)
    tls = runner.run_case(
        scenarios.get("T01"), client, server, layout=layout, pki=test_pki, **OK_LIMITS
    )

    assert dtls.outcome is Outcome.UNSUPPORTED and not dtls.server.started
    assert tls.outcome is Outcome.PASS, tls.reason


def test_adapter_refusing_a_declared_transport_is_unsupported(tmp_path, layout, test_pki):
    t01 = scenarios.get("T01")
    result = run(tmp_path, layout, test_pki, scenario=t01, server_flags=["--implements=dtls"])

    assert result.outcome is Outcome.UNSUPPORTED
    assert result.reason == "server: tls transport not implemented"


def test_numeric_mtu_with_tls_is_usage_error(tmp_path, layout, test_pki):
    t01 = scenarios.get("T01")
    client_options = dataclasses.replace(t01.client, mtu=1500)
    scenario = dataclasses.replace(t01, client=client_options)
    result = run(tmp_path, layout, test_pki, scenario=scenario, server_grace=0.5)

    assert result.outcome is Outcome.ERROR
    assert result.reason.endswith("usage error: --mtu must be default with --transport=tls")


@dataclasses.dataclass
class Datagram:
    index: int
    direction: str
    payload: bytes


class Relay:
    """Minimal real UDP relay standing in for the proxy at the path-factory seam."""

    def __init__(self, server: tuple[str, int], conditions: PathConditions):
        self.conditions = conditions
        self.trace: list[Datagram] = []
        self._front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._front.bind(("127.0.0.1", 0))
        self._back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._back.connect(server)
        self._stop_r, self._stop_w = socket.socketpair()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        return self._front.getsockname()

    def __enter__(self) -> Relay:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop_w.send(b"x")
        self._thread.join()
        for s in (self._front, self._back, self._stop_r, self._stop_w):
            s.close()

    def _loop(self) -> None:
        client = None
        while True:
            ready, _, _ = select.select([self._front, self._back, self._stop_r], [], [])
            if self._stop_r in ready:
                return
            if self._front in ready:
                data, client = self._front.recvfrom(65535)
                self.trace.append(Datagram(len(self.trace), "c2s", data))
                self._back.send(data)
            if self._back in ready:
                try:
                    data = self._back.recv(65535)
                except ConnectionRefusedError:
                    continue
                self.trace.append(Datagram(len(self.trace), "s2c", data))
                if client is not None:
                    self._front.sendto(data, client)


def test_path_factory_routes_client_and_records_trace(tmp_path, layout, test_pki):
    seen = []

    def factory(server, conditions):
        seen.append((server, conditions))
        return Relay(server, conditions)

    scenario = scenarios.get("S08")
    result = run(tmp_path, layout, test_pki, scenario=scenario, path_factory=factory)

    assert result.outcome is Outcome.PASS, result.reason
    assert result.path.proxied is True
    assert result.path.impairments == [str(Impairment.REORDER_CH1)]
    [(server_addr, conditions)] = seen
    assert conditions == scenario.path
    ready = json.loads((case_dir(layout, scenario) / "server.stdout").read_text().splitlines()[0])
    assert server_addr == ("127.0.0.1", ready["port"])
    assert f"--port={ready['port']}" not in result.client.command
    trace = [
        json.loads(line)
        for line in (case_dir(layout, scenario) / "trace.jsonl").read_text().splitlines()
    ]
    assert trace == [
        {"index": 0, "direction": "c2s", "payload": b"ping".hex()},
        {"index": 1, "direction": "s2c", "payload": b"pong".hex()},
    ]
    assert result.trace == "trace.jsonl"


@pytest.mark.parametrize("scenario_id", ["S08", "S09", "S03+split"])
def test_impaired_and_split_scenarios_run_through_the_proxy(
    tmp_path, layout, test_pki, scenario_id
):
    scenario = scenarios.get(scenario_id)
    result = run(tmp_path, layout, test_pki, scenario=scenario)

    # Plain UDP has no ClientHello, so the rules forward everything.
    assert result.outcome is Outcome.PASS, result.reason
    assert result.path.proxied is True
    assert result.path.pmtu == scenario.path.pmtu
    assert result.path.impairments == [str(i) for i in scenario.path.impairments]
    assert result.path.split_ch1 == scenario.path.split_ch1
    assert result.path.actions == {}


class _Boom(Rule):
    def on_packet(self, packet, now):
        if packet.direction == "c2s":
            raise ValueError("rule exploded")
        return FORWARD


def test_path_failure_is_error(tmp_path, layout, test_pki):
    def factory(server, conditions):
        return UdpProxy(server, pmtu=conditions.pmtu, rules=[_Boom()])

    result = run(tmp_path, layout, test_pki, path_factory=factory, case_timeout=2)

    assert result.outcome is Outcome.ERROR
    assert result.reason == "path failed: UDP proxy thread failed"
    assert result.path.proxied is True
    assert result.client.killed


def test_path_factory_refusal_is_error(tmp_path, layout, test_pki):
    def factory(server, conditions):
        raise ValueError("unknown impairment 'reorder-ch1'")

    result = run(tmp_path, layout, test_pki, scenario=scenarios.get("S08"), path_factory=factory)

    assert result.outcome is Outcome.ERROR
    assert result.reason == "path setup failed: unknown impairment 'reorder-ch1'"
    assert result.path.proxied is False
    # The path is set up once the server has reported its port, so the server ran and was killed.
    assert result.server.killed
    assert not result.client.started


def test_usage_error(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--bogus=1"], server_grace=0.5)

    assert result.outcome is Outcome.ERROR
    assert result.reason.startswith("usage error (client): ")
    assert "unrecognized arguments: --bogus=1" in result.reason
    assert result.client.exit_code == 64


def test_ready_line_without_port_is_error(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--behave=ready-no-port"])

    assert result.outcome is Outcome.ERROR
    assert result.reason == "server: ready line without a valid port: {'event': 'ready'}"
    assert result.server.killed
    assert not result.client.started


@pytest.mark.parametrize(
    ("report", "reason"),
    [
        (
            ["--report=hrr=false", "--report=hrr_cookie=true"],
            "server: result 'hrr_cookie' must be false when 'hrr' is false",
        ),
        (
            ["--report=hrr=false", "--report=hrr_cookie=false"],
            "server: result 'hrr_group' must be false when 'hrr' is false",
        ),
        (["--report=hrr_group=1"], "server: result 'hrr_group' has wrong type: 1"),
        (['--report=resumed="yes"'], "server: result 'resumed' has wrong type: 'yes'"),
    ],
)
def test_hrr_reason_fields_are_validated(tmp_path, layout, test_pki, report, reason):
    result = run(tmp_path, layout, test_pki, server_flags=report)

    assert result.outcome is Outcome.ERROR
    assert result.reason == reason


def test_hrr_reason_expectations(tmp_path, layout, test_pki):
    # S04 expects an HRR that carries a cookie and does not ask for a new key share.
    s04 = scenarios.get("S04")
    report = ["--report=hrr=true", "--report=hrr_cookie=false", "--report=hrr_group=true"]
    result = run(tmp_path, layout, test_pki, server_flags=report, scenario=s04)

    assert result.outcome is Outcome.FAIL
    assert result.reason == (
        "server reported hrr_cookie=False, expected True; "
        "server reported hrr_group=True, expected False"
    )
    assert "--validate=cookie" in result.server.command
    assert "--mtu=1280" in result.server.command


def test_variant_is_passed_and_recorded(tmp_path, layout, test_pki):
    install(tmp_path, "echo", variants="client fast: Client-only path\n")
    found = implementations.discover(tmp_path / "implementations", tmp_path / "build")
    entries = {i.id: i for i in found}
    client, server = entries["echo+fast"], entries["echo"]

    result = runner.run_case(S01, client, server, layout=layout, pki=test_pki, **OK_LIMITS)

    assert result.outcome is Outcome.PASS, result.reason
    assert (result.client.implementation, result.client.variant) == ("echo", "fast")
    assert (result.server.implementation, result.server.variant) == ("echo", "default")
    assert "--variant=fast" in result.client.command
    assert "--variant=default" in result.server.command
    d = layout.case_dir("S01", "echo+fast", "echo")
    assert d.name == "echo+fast__echo"
    assert "variant=fast" in (d / "client.stderr").read_text()
    assert read_result(d / RESULT_FILE) == result


def test_variant_role_is_enforced(tmp_path, layout, test_pki):
    install(tmp_path, "echo", variants="client fast: Client-only path\n")
    found = implementations.discover(tmp_path / "implementations", tmp_path / "build")
    entries = {i.id: i for i in found}

    with pytest.raises(ValueError, match="echo\\+fast is not a server entry"):
        runner.run_case(S01, entries["echo"], entries["echo+fast"], layout=layout, pki=test_pki)

    # Bypassing the runner's guard, the adapter itself rejects the variant in the wrong role.
    server = dataclasses.replace(entries["echo+fast"], roles=BOTH_ROLES)
    result = runner.run_case(S01, entries["echo"], server, layout=layout, pki=test_pki, **OK_LIMITS)

    assert result.outcome is Outcome.ERROR
    assert "--variant=fast is not a server variant" in result.reason
    assert result.reason.startswith("usage error (server): ")


def test_repeated_option_is_usage_error(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, server_flags=["--groups=X25519"])

    assert result.outcome is Outcome.ERROR
    assert result.reason.endswith("usage error: --groups given more than once")
    assert result.server.exit_code == 64


def test_key_share_outside_groups_is_usage_error(tmp_path, layout, test_pki):
    client_options = ClientOptions(groups=("X25519MLKEM768",), key_share="X25519", mtu=1500)
    scenario = dataclasses.replace(S01, client=client_options)
    result = run(tmp_path, layout, test_pki, scenario=scenario, server_grace=0.5)

    assert result.outcome is Outcome.ERROR
    assert result.reason.endswith("usage error: --key-share=X25519 is not in --groups")
    assert result.client.exit_code == 64
