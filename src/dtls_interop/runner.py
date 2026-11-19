"""Run one (scenario, client, server) case through the adapters per docs/shim-interface.md."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from dtls_interop.implementations import Implementation
from dtls_interop.pki import TestPki
from dtls_interop.results import (
    SCHEMA_VERSION,
    AdapterRecord,
    CaseResult,
    Outcome,
    PathRecord,
    RunLayout,
    utc_now,
    write_result,
)
from dtls_interop.scenarios import PathConditions, Scenario, Transport

LOOPBACK = "127.0.0.1"
DEFAULT_READY_TIMEOUT = 10.0
DEFAULT_CASE_TIMEOUT = 30.0
# How long the server may take to exit after the client has exited.
DEFAULT_SERVER_GRACE = 5.0
TRACE_FILE = "trace.jsonl"

# Bound on draining stdout after the kill; only a process that left its group can hold it open.
_DRAIN_TIMEOUT = 5.0
# Result line fields: (type, null allowed).
_RESULT_FIELDS = {
    "ok": (bool, False),
    "version": (str, True),
    "group": (str, True),
    "hrr": (bool, True),
    "error": (str, True),
}

type Address = tuple[str, int]


class PathHandle(Protocol):
    """An active network path between client and server, e.g. the UDP proxy.

    If it also has a `trace` attribute (a list of datagrams), the runner writes it to trace.jsonl.
    """

    @property
    def address(self) -> Address: ...


# Called with the server address and the scenario's path conditions; entered before any adapter
# starts and exited after both are reaped. May raise to refuse unknown impairments.
type PathFactory = Callable[[Address, PathConditions], AbstractContextManager[PathHandle]]


def free_udp_port(host: str = LOOPBACK) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def implementation_version(impl: Implementation) -> str | None:
    """First line of the .built marker, if build.sh wrote one."""
    try:
        text = (impl.prefix / ".built").read_text().strip()
    except OSError:
        return None
    return text.splitlines()[0] if text else None


def server_command(impl: Implementation, scenario: Scenario, port: int, pki: TestPki) -> list[str]:
    s = scenario.server
    return [
        str(impl.adapter),
        "--role=server",
        f"--host={LOOPBACK}",
        f"--port={port}",
        f"--groups={','.join(s.groups)}",
        f"--mtu={s.mtu}",
        f"--validate={s.validate}",
        f"--cert={pki.server_cert}",
        f"--key={pki.server_key}",
        f"--ca={pki.ca_cert}",
    ]


def client_command(
    impl: Implementation, scenario: Scenario, address: Address, pki: TestPki
) -> list[str]:
    c = scenario.client
    return [
        str(impl.adapter),
        "--role=client",
        f"--host={address[0]}",
        f"--port={address[1]}",
        f"--groups={','.join(c.groups)}",
        f"--key-share={c.key_share}",
        f"--mtu={c.mtu}",
        f"--ca={pki.ca_cert}",
    ]


def parse_result_line(lines: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    """Return (final result object, protocol problem). stdout must hold only JSON lines."""
    events = []
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None, f"non-JSON stdout line {line[:120]!r}"
        if not isinstance(obj, dict) or not isinstance(obj.get("event"), str):
            return None, f"stdout line is not an event object: {line[:120]!r}"
        events.append(obj)
    if not events or events[-1]["event"] != "result":
        return None, "no result line as last stdout line"
    result = events[-1]
    for key, (tp, nullable) in _RESULT_FIELDS.items():
        if key not in result:
            return result, f"result line lacks {key!r}"
        value = result[key]
        if not (isinstance(value, tp) or (nullable and value is None)):
            return result, f"result {key!r} has wrong type: {value!r}"
    return result, None


class _Adapter:
    """One adapter process: stdout lines are collected by a thread and teed to a log."""

    def __init__(self, role: str, impl: Implementation, command: list[str], case_dir: Path):
        self.role = role
        self.impl = impl
        self.command = command
        self.stdout_name = f"{role}.stdout"
        self.stderr_name = f"{role}.stderr"
        self.case_dir = case_dir
        self.proc: subprocess.Popen[bytes] | None = None
        self.lines: list[str] = []
        self.eof = False
        self.killed = False
        self.exit_code: int | None = None
        self.duration: float | None = None
        self.result: dict[str, Any] | None = None
        self.problem: str | None = None
        self._cond = threading.Condition()
        self._reader: threading.Thread | None = None
        self._t0 = 0.0

    @property
    def started(self) -> bool:
        return self.proc is not None

    def start(self) -> None:
        with open(self.case_dir / self.stderr_name, "wb") as err:
            self._t0 = time.monotonic()
            # Own session so killpg also reaches anything the adapter script spawned.
            self.proc = subprocess.Popen(
                self.command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=err,
                start_new_session=True,
            )
        self._reader = threading.Thread(target=self._read, name=f"{self.role}-stdout", daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        with open(self.case_dir / self.stdout_name, "wb") as log:
            for raw in self.proc.stdout:
                log.write(raw)
                log.flush()
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                with self._cond:
                    self.lines.append(line)
                    self._cond.notify_all()
        with self._cond:
            self.eof = True
            self._cond.notify_all()

    def wait_ready(self, deadline: float) -> bool:
        def seen() -> bool:
            return any(_is_ready(line) for line in self.lines)

        with self._cond:
            while not seen() and not self.eof:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            return seen()

    def wait_exit(self, deadline: float) -> bool:
        assert self.proc is not None
        try:
            self.proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
        self._exited()
        return True

    def _exited(self) -> None:
        assert self.proc is not None
        if self.duration is None:
            self.duration = time.monotonic() - self._t0
            self.exit_code = self.proc.returncode

    def stop(self) -> None:
        """Kill the whole process group, reap, and drain stdout. Idempotent."""
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.killed = True
            self.duration = time.monotonic() - self._t0
        else:
            self._exited()
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait()
        assert self._reader is not None and self.proc.stdout is not None
        self._reader.join(_DRAIN_TIMEOUT)
        if self._reader.is_alive():
            self.problem = "stdout still open after kill (a process left the adapter's group)"
            return
        self.proc.stdout.close()
        if not self.killed:
            self.result, self.problem = parse_result_line(self.lines)

    def record(self) -> AdapterRecord:
        return AdapterRecord(
            implementation=self.impl.name,
            implementation_version=implementation_version(self.impl),
            command=self.command,
            started=self.started,
            exit_code=self.exit_code,
            killed=self.killed,
            duration_s=None if self.duration is None else round(self.duration, 6),
            result=self.result,
            stdout_log=self.stdout_name if self.started else None,
            stderr_log=self.stderr_name if self.started else None,
        )

    def error_text(self) -> str:
        err = (self.result or {}).get("error")
        return f"{self.role}: {err}" if err else f"{self.role}: exit {self.exit_code}"


def _is_ready(line: str) -> bool:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and obj.get("event") == "ready"


def _signal_name(code: int) -> str:
    try:
        return signal.Signals(-code).name
    except ValueError:
        return f"signal {-code}"


def _precheck(scenario: Scenario, path_factory: PathFactory | None) -> str | None:
    if scenario.transport is not Transport.DTLS:
        return f"{scenario.transport} transport is not in the adapter contract"
    if scenario.resumption:
        return "PSK resumption is not implemented in the runner"
    if scenario.path.impairments and path_factory is None:
        return "path impairments not available"
    return None


def _expectation_mismatches(scenario: Scenario, sides: list[_Adapter]) -> list[str]:
    exp = scenario.expected
    out = []
    for side in sides:
        result = side.result or {}
        for key, want in (("version", exp.version), ("group", exp.group), ("hrr", exp.hrr)):
            got = result.get(key)
            if want is not None and got is not None and got != want:
                out.append(f"{side.role} reported {key}={got!r}, expected {want!r}")
    return out


def _json_default(o: object) -> Any:
    if isinstance(o, bytes | bytearray):
        return o.hex()
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return dataclasses.asdict(o)
    if isinstance(o, Enum):
        return o.value
    return str(o)


def _write_trace(case_dir: Path, path: object) -> str | None:
    trace = getattr(path, "trace", None)
    if trace is None:
        return None
    with open(case_dir / TRACE_FILE, "w") as f:
        for datagram in trace:
            f.write(json.dumps(datagram, default=_json_default) + "\n")
    return TRACE_FILE


@dataclasses.dataclass
class _Limits:
    ready_timeout: float
    case_timeout: float
    server_grace: float


def _classify(
    scenario: Scenario, server: _Adapter, client: _Adapter, ready: bool, limits: _Limits
) -> tuple[Outcome, str | None]:
    sides = [a for a in (server, client) if a.started]
    for a in sides:
        if a.exit_code == 2:
            return Outcome.UNSUPPORTED, a.error_text()
    for a in sides:
        if a.exit_code is not None and a.exit_code < 0:
            return Outcome.FAIL, f"{a.role} crashed ({_signal_name(a.exit_code)})"
    for a in sides:
        if a.exit_code not in (None, 0, 1):
            return Outcome.ERROR, f"{a.role} exited with unexpected code {a.exit_code}"
    if not ready:
        if server.exit_code is not None:
            return Outcome.ERROR, f"server exited before ready ({server.error_text()})"
        return Outcome.ERROR, f"server not ready within {limits.ready_timeout:g}s"
    for a in sides:
        if a.exit_code is None:
            continue
        if a.problem:
            return Outcome.ERROR, f"{a.role}: {a.problem}"
        assert a.result is not None
        if a.result["ok"] != (a.exit_code == 0):
            return Outcome.ERROR, f"{a.role}: exit {a.exit_code} contradicts ok={a.result['ok']}"
    if client.killed:
        return Outcome.TIMEOUT, f"client did not finish within {limits.case_timeout:g}s"
    if server.killed:
        if client.exit_code == 1:
            return Outcome.FAIL, client.error_text()
        return Outcome.TIMEOUT, "server did not exit after the client finished"
    failed = [a.error_text() for a in sides if a.exit_code == 1]
    if failed:
        return Outcome.FAIL, "; ".join(failed)
    mismatches = _expectation_mismatches(scenario, sides)
    if mismatches:
        return Outcome.FAIL, "; ".join(mismatches)
    return Outcome.PASS, None


def _execute(
    scenario: Scenario,
    server: _Adapter,
    client: _Adapter,
    server_addr: Address,
    pki: TestPki,
    path_factory: PathFactory | None,
    limits: _Limits,
) -> tuple[Outcome, str | None, object | None]:
    """Returns (outcome, reason, active path or None)."""
    deadline = time.monotonic() + limits.case_timeout
    with contextlib.ExitStack() as stack:
        path = None
        if path_factory is not None:
            try:
                path = stack.enter_context(path_factory(server_addr, scenario.path))
            except Exception as e:  # plugin boundary: a refused or broken path is a recorded error
                return Outcome.ERROR, f"path setup failed: {e}", None
            client.command = client_command(client.impl, scenario, path.address, pki)
        try:
            server.start()
            ready = server.wait_ready(min(deadline, time.monotonic() + limits.ready_timeout))
            if ready:
                client.start()
                if client.wait_exit(deadline):
                    server.wait_exit(min(deadline, time.monotonic() + limits.server_grace))
        except OSError as e:
            return Outcome.ERROR, f"cannot start adapter: {e}", path
        finally:
            client.stop()
            server.stop()
    return *_classify(scenario, server, client, ready, limits), path


def run_case(
    scenario: Scenario,
    client_impl: Implementation,
    server_impl: Implementation,
    *,
    layout: RunLayout,
    pki: TestPki,
    path_factory: PathFactory | None = None,
    ready_timeout: float = DEFAULT_READY_TIMEOUT,
    case_timeout: float = DEFAULT_CASE_TIMEOUT,
    server_grace: float = DEFAULT_SERVER_GRACE,
) -> CaseResult:
    """Run one case, write <case dir>/result.json, and return the result.

    Both adapter process groups are killed and reaped on every exit path.
    """
    case_dir = layout.case_dir(scenario.id, client_impl.name, server_impl.name)
    case_dir.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    t0 = time.monotonic()
    server_addr = (LOOPBACK, free_udp_port())
    server_cmd = server_command(server_impl, scenario, server_addr[1], pki)
    server = _Adapter("server", server_impl, server_cmd, case_dir)
    client_cmd = client_command(client_impl, scenario, server_addr, pki)
    client = _Adapter("client", client_impl, client_cmd, case_dir)
    limits = _Limits(ready_timeout, case_timeout, server_grace)

    path = None
    precheck = _precheck(scenario, path_factory)
    if precheck is not None:
        outcome, reason = Outcome.ERROR, precheck
    else:
        outcome, reason, path = _execute(
            scenario, server, client, server_addr, pki, path_factory, limits
        )

    result = CaseResult(
        schema_version=SCHEMA_VERSION,
        run_id=layout.run_id,
        timestamp=timestamp.isoformat(timespec="milliseconds"),
        scenario=scenario.id,
        outcome=outcome,
        reason=reason,
        duration_s=round(time.monotonic() - t0, 6),
        client=client.record(),
        server=server.record(),
        path=PathRecord(
            proxied=path is not None,
            pmtu=scenario.path.pmtu,
            impairments=[str(i) for i in scenario.path.impairments],
        ),
        trace=_write_trace(case_dir, path) if path is not None else None,
    )
    write_result(case_dir, result)
    return result
