"""Run one (scenario, client, server) case through the adapters per docs/shim-interface.md."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from dtls_interop.implementations import CLIENT, SERVER, Implementation
from dtls_interop.path import TraceSummary, proxy_path, summarize
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
    "hrr_cookie": (bool, True),
    "hrr_group": (bool, True),
    "error": (str, True),
}
EXIT_UNSUPPORTED = 2
EXIT_USAGE = 64
# Exit codes that decide the outcome whatever the peer does, so the peer is stopped at once.
_DECISIVE_EXITS = frozenset({EXIT_UNSUPPORTED, EXIT_USAGE})
_POLL_INTERVAL = 0.02

type Address = tuple[str, int]


class PathHandle(Protocol):
    """An active network path between client and server, e.g. the UDP proxy.

    If it also has a `trace` attribute (a list of datagrams), the runner writes it to trace.jsonl.
    """

    @property
    def address(self) -> Address: ...


# Called with the server's bound address and the path conditions once the server is ready;
# exited after both adapters are reaped. May raise to refuse unknown impairments.
type PathFactory = Callable[[Address, PathConditions], AbstractContextManager[PathHandle]]


def server_command(impl: Implementation, scenario: Scenario, pki: TestPki) -> list[str]:
    """The server binds port 0 and reports the bound port in its ready line."""
    s = scenario.server
    return [
        str(impl.adapter),
        "--role=server",
        f"--variant={impl.variant}",
        f"--host={LOOPBACK}",
        "--port=0",
        f"--groups={','.join(s.groups)}",
        f"--mtu={s.mtu}",
        f"--ca={pki.ca_cert}",
        f"--validate={s.validate}",
        f"--cert={pki.server_cert}",
        f"--key={pki.server_key}",
    ]


def client_command(
    impl: Implementation, scenario: Scenario, address: Address, pki: TestPki
) -> list[str]:
    c = scenario.client
    return [
        str(impl.adapter),
        "--role=client",
        f"--variant={impl.variant}",
        f"--host={address[0]}",
        f"--port={address[1]}",
        f"--groups={','.join(c.groups)}",
        f"--mtu={c.mtu}",
        f"--ca={pki.ca_cert}",
        f"--key-share={c.key_share}",
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
    if result["hrr"] is False:
        for key in ("hrr_cookie", "hrr_group"):
            if result[key] is not False:
                return result, f"result {key!r} must be false when 'hrr' is false"
    return result, None


def ready_port(event: dict[str, Any]) -> int | None:
    port = event.get("port")
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        return port
    return None


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
        self.ready_event: dict[str, Any] | None = None
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
                event = _ready_event(line) if self.ready_event is None else None
                with self._cond:
                    self.lines.append(line)
                    if event is not None:
                        self.ready_event = event
                    self._cond.notify_all()
        with self._cond:
            self.eof = True
            self._cond.notify_all()

    def wait_ready(self, deadline: float) -> dict[str, Any] | None:
        """The first {"event": "ready"} object, or None at EOF or the deadline."""
        with self._cond:
            while self.ready_event is None and not self.eof:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            return self.ready_event

    def wait_exit(self, deadline: float) -> bool:
        assert self.proc is not None
        try:
            self.proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
        self._exited()
        return True

    def poll_exit(self) -> bool:
        assert self.proc is not None
        if self.proc.poll() is None:
            return False
        self._exited()
        return True

    @property
    def decisive_exit(self) -> bool:
        return self.exit_code in _DECISIVE_EXITS

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
            variant=self.impl.variant,
            implementation_version=self.impl.version,
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

    def stderr_tail(self) -> str:
        try:
            lines = (self.case_dir / self.stderr_name).read_text(errors="replace").splitlines()
        except OSError:
            return ""
        return next((line.strip() for line in reversed(lines) if line.strip()), "")


def _ready_event(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) and obj.get("event") == "ready" else None


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
    if scenario.path.split_ch1 is not None and path_factory is None:
        return "CH1 split needs the proxy"
    return None


def _expectation_mismatches(scenario: Scenario, sides: list[_Adapter]) -> list[str]:
    exp = scenario.expected
    out = []
    for side in sides:
        result = side.result or {}
        for key in ("version", "group", "hrr", "hrr_cookie", "hrr_group"):
            want, got = getattr(exp, key), result.get(key)
            if want is not None and got is not None and got != want:
                out.append(f"{side.role} reported {key}={got!r}, expected {want!r}")
    return out


def _fragmentation_mismatches(scenario: Scenario, summary: TraceSummary) -> list[str]:
    out = []
    checks = (
        ("CH1", scenario.expected.ch1_fragmented, summary.ch1),
        ("CH2", scenario.expected.ch2_fragmented, summary.ch2),
    )
    for name, want, sent in checks:
        if want is None or sent is None or (sent.fragments > 1) == want:
            continue
        got = f"in {sent.fragments} fragments" if sent.fragments > 1 else "unfragmented"
        out.append(f"client sent {name} {got}, expected {'fragmented' if want else 'unfragmented'}")
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
    scenario: Scenario,
    server: _Adapter,
    client: _Adapter,
    ready: bool,
    limits: _Limits,
    summary: TraceSummary | None,
) -> tuple[Outcome, str | None]:
    sides = [a for a in (server, client) if a.started]
    for a in sides:
        if a.exit_code == EXIT_USAGE:
            err = (a.result or {}).get("error") or a.stderr_tail()
            return Outcome.ERROR, f"usage error ({a.role}): {err}"
    for a in sides:
        if a.exit_code == EXIT_UNSUPPORTED:
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
    if summary is not None:
        mismatches += _fragmentation_mismatches(scenario, summary)
    if mismatches:
        return Outcome.FAIL, "; ".join(mismatches)
    return Outcome.PASS, None


class _Abort(Exception):
    """Stop the case early with outcome error and this reason."""


class _PathFailed(Exception):
    """The path raised while shutting down, e.g. a proxy rule failed on a datagram."""


class _GuardedPath(AbstractContextManager[PathHandle]):
    def __init__(self, cm: AbstractContextManager[PathHandle]) -> None:
        self._cm = cm

    def __enter__(self) -> PathHandle:
        return self._cm.__enter__()

    def __exit__(self, *exc_info: Any) -> bool | None:
        if exc_info[0] is not None:
            return self._cm.__exit__(*exc_info)
        try:
            return self._cm.__exit__(*exc_info)
        except Exception as e:
            raise _PathFailed(str(e)) from e


def _wait_client(client: _Adapter, server: _Adapter, deadline: float) -> None:
    """Until the client exits, the server exits with a decisive code, or the deadline passes."""
    while not client.wait_exit(min(deadline, time.monotonic() + _POLL_INTERVAL)):
        if time.monotonic() >= deadline or (server.poll_exit() and server.decisive_exit):
            return


def _execute(
    scenario: Scenario,
    server: _Adapter,
    client: _Adapter,
    pki: TestPki,
    path_factory: PathFactory | None,
    limits: _Limits,
) -> tuple[str | None, bool, object | None]:
    """Returns (reason the case was aborted with, server became ready, path or None)."""
    deadline = time.monotonic() + limits.case_timeout
    path = None
    ready = None
    try:
        with contextlib.ExitStack() as stack:
            try:
                server.start()
                ready_deadline = min(deadline, time.monotonic() + limits.ready_timeout)
                ready = server.wait_ready(ready_deadline)
                if ready is None:
                    # stdout closes just before the process exits; collect the exit code.
                    server.wait_exit(ready_deadline)
                    return None, False, path
                port = ready_port(ready)
                if port is None:
                    raise _Abort(f"server: ready line without a valid port: {ready!r}")
                address: Address = (LOOPBACK, port)
                if path_factory is not None:
                    try:
                        cm = path_factory(address, scenario.path)
                        path = stack.enter_context(_GuardedPath(cm))
                    except Exception as e:  # plugin boundary: a refusal is a recorded error
                        raise _Abort(f"path setup failed: {e}") from e
                    address = path.address
                client.command = client_command(client.impl, scenario, address, pki)
                client.start()
                _wait_client(client, server, deadline)
                if client.exit_code is not None and not client.decisive_exit:
                    server.wait_exit(min(deadline, time.monotonic() + limits.server_grace))
            except _Abort as e:
                return str(e), ready is not None, path
            except OSError as e:
                return f"cannot start adapter: {e}", ready is not None, path
            finally:
                client.stop()
                server.stop()
    except _PathFailed as e:
        return f"path failed: {e}", True, path
    return None, True, path


def run_case(
    scenario: Scenario,
    client_impl: Implementation,
    server_impl: Implementation,
    *,
    layout: RunLayout,
    pki: TestPki,
    path_factory: PathFactory | None = proxy_path,
    ready_timeout: float = DEFAULT_READY_TIMEOUT,
    case_timeout: float = DEFAULT_CASE_TIMEOUT,
    server_grace: float = DEFAULT_SERVER_GRACE,
) -> CaseResult:
    """Run one case, write <case dir>/result.json, and return the result.

    The path defaults to the UDP proxy; None connects the client to the server directly.
    Both adapter process groups are killed and reaped on every exit path.
    """
    for impl, role in ((client_impl, CLIENT), (server_impl, SERVER)):
        if role not in impl.roles:
            raise ValueError(f"{impl.id} is not a {role} entry")
    case_dir = layout.case_dir(scenario.id, client_impl.id, server_impl.id)
    case_dir.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    t0 = time.monotonic()
    server = _Adapter("server", server_impl, server_command(server_impl, scenario, pki), case_dir)
    # The client's command is known once the server has reported its port.
    client = _Adapter("client", client_impl, [], case_dir)
    limits = _Limits(ready_timeout, case_timeout, server_grace)

    path = None
    summary = None
    precheck = _precheck(scenario, path_factory)
    if precheck is not None:
        outcome, reason = Outcome.ERROR, precheck
    else:
        abort, ready, path = _execute(scenario, server, client, pki, path_factory, limits)
        trace = getattr(path, "trace", None)
        summary = summarize(trace) if trace is not None else None
        if abort is not None:
            outcome, reason = Outcome.ERROR, abort
        else:
            outcome, reason = _classify(scenario, server, client, ready, limits, summary)

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
            split_ch1=scenario.path.split_ch1,
            actions=summary.actions if summary is not None else {},
        ),
        trace=_write_trace(case_dir, path) if path is not None else None,
        ch1_size=summary.ch1.size if summary and summary.ch1 else None,
        ch1_fragments=summary.ch1.fragments if summary and summary.ch1 else None,
        ch2_size=summary.ch2.size if summary and summary.ch2 else None,
        ch2_fragments=summary.ch2.fragments if summary and summary.ch2 else None,
    )
    write_result(case_dir, result)
    return result
