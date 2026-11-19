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

from dtls_interop import runner, scenarios
from dtls_interop.results import (
    RESULT_FILE,
    SCHEMA_VERSION,
    Outcome,
    RunLayout,
    SchemaError,
    read_result,
    read_run,
)
from dtls_interop.scenarios import Impairment, PathConditions

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
            "error": None,
        }
        assert side.duration_s is not None and side.duration_s >= 0
    assert "--role=server" in result.server.command
    assert "--validate=off" in result.server.command
    assert "--key-share=X25519" in result.client.command
    assert result.path.proxied is False
    assert result.path.pmtu == 1500
    assert result.trace is None
    assert result.ch1_size is None and result.ch2_fragments is None

    d = case_dir(layout)
    assert d.parent.parent.parent.name == layout.started.strftime("%Y-%m-%d")
    assert '"event": "ready"' in (d / result.server.stdout_log).read_text()
    assert re.search(r"pid=\d+", (d / result.client.stderr_log).read_text())


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


def test_client_unsupported(tmp_path, layout, test_pki):
    result = run(tmp_path, layout, test_pki, client_flags=["--behave=exit2"], server_grace=0.5)

    assert result.outcome is Outcome.UNSUPPORTED
    assert result.client.exit_code == 2
    # The server never got a ping and was killed after the grace period.
    assert result.server.killed and result.server.exit_code is None


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
    result = run(tmp_path, layout, test_pki, server_flags=["--report-group=X25519MLKEM768"])

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
        ("S10", "PSK resumption is not implemented in the runner"),
        ("T01", "tls transport is not in the adapter contract"),
    ],
)
def test_unrunnable_scenarios_are_errors(tmp_path, layout, test_pki, scenario_id, reason):
    scenario = scenarios.get(scenario_id)
    result = run(tmp_path, layout, test_pki, scenario=scenario)

    assert result.outcome is Outcome.ERROR
    assert result.reason == reason
    assert not result.client.started and not result.server.started
    assert read_result(case_dir(layout, scenario) / RESULT_FILE) == result


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
    assert f"--port={server_addr[1]}" in result.server.command
    assert f"--port={server_addr[1]}" not in result.client.command
    trace = [json.loads(line) for line in (case_dir(layout, scenario) / "trace.jsonl").open()]
    assert trace == [
        {"index": 0, "direction": "c2s", "payload": b"ping".hex()},
        {"index": 1, "direction": "s2c", "payload": b"pong".hex()},
    ]
    assert result.trace == "trace.jsonl"


def test_path_factory_refusal_is_error(tmp_path, layout, test_pki):
    def factory(server, conditions):
        raise ValueError("unknown impairment 'reorder-ch1'")

    result = run(tmp_path, layout, test_pki, scenario=scenarios.get("S08"), path_factory=factory)

    assert result.outcome is Outcome.ERROR
    assert result.reason == "path setup failed: unknown impairment 'reorder-ch1'"
    assert result.path.proxied is False
    assert not result.server.started


def test_free_udp_port_is_bindable():
    port = runner.free_udp_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", port))
