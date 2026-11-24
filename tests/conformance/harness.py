"""Drive adapters as the runner does and check their behaviour against docs/shim-interface.md."""

from __future__ import annotations

import contextlib
import errno
import json
import os
import signal
import socket
import subprocess
import threading
import time
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from dtls_interop.hello_trace import FlowHellos, trace_flows
from dtls_interop.implementations import CLIENT, DEFAULT_VARIANT, SERVER, Implementation
from dtls_interop.pki import TestPki
from dtls_interop.proxy import FORWARD, Datagram, Packet, Rule, UdpProxy, Verdict, drop
from dtls_interop.records import (
    HRR_RANDOM,
    HS_CLIENT_HELLO,
    HS_SERVER_HELLO,
    CiphertextRecord,
    HandshakeFragment,
    HelloInfo,
    ParsedDatagram,
    parse_datagram,
    parse_hello,
    reassemble,
)
from dtls_interop.runner import parse_result_line
from dtls_interop.tcp_proxy import TcpProxy

HOST = "127.0.0.1"
# A loopback port nothing listens on, for clients that must fail before connecting.
UNUSED_PORT = 9
READY_TIMEOUT = 10.0
RUN_TIMEOUT = 20.0
SERVER_GRACE = 5.0
EXIT_OK, EXIT_FAIL, EXIT_UNSUPPORTED, EXIT_USAGE = 0, 1, 2, 64
IP_UDP_OVERHEAD = 48
TEARDOWN_WAIT = 2.0

# IANA TLS Supported Groups registry.
GROUP_CODES = {
    "secp256r1": 0x0017,
    "secp384r1": 0x0018,
    "X25519": 0x001D,
    "SecP256r1MLKEM768": 0x11EB,
    "X25519MLKEM768": 0x11EC,
    "SecP384r1MLKEM1024": 0x11ED,
}
X25519, MLKEM, P256 = "X25519", "X25519MLKEM768", "secp256r1"

_COMMON = ("role", "variant", "host", "port", "groups", "transport", "resume", "mtu", "ca")
ROLE_OPTIONS = {
    CLIENT: (*_COMMON, "key-share"),
    SERVER: (*_COMMON, "validate", "cert", "key"),
}
HANDSHAKE_KEYS = ("version", "group", "hrr", "hrr_cookie", "hrr_group", "resumed")
RESULT_KEYS = {"event", "ok", *HANDSHAKE_KEYS, "error"}
VERSIONS = {"dtls": "DTLSv1.3", "tls": "TLSv1.3"}

type Options = list[tuple[str, str]]


@dataclass(frozen=True)
class Subject:
    """The entry under test in one role, and the same implementation's default entry as peer."""

    impl: Implementation
    role: str
    peer: Implementation


@dataclass(frozen=True)
class PairCase:
    client: Implementation
    server: Implementation


def default_entry(entries: Sequence[Implementation], impl: Implementation) -> Implementation:
    return next(e for e in entries if e.name == impl.name and e.variant == DEFAULT_VARIANT)


def subjects(entries: Sequence[Implementation], role: str | None = None) -> list[Subject]:
    """Every entry in every role it lists (variant roles respected)."""
    return [
        Subject(e, r, default_entry(entries, e))
        for e in entries
        for r in (CLIENT, SERVER)
        if r in e.roles and role in (None, r)
    ]


def pair_cases(entries: Sequence[Implementation]) -> list[PairCase]:
    """Each entry once in each of its roles, against its implementation's default entry."""
    out = []
    for e in entries:
        default = default_entry(entries, e)
        if SERVER in e.roles:
            out.append(PairCase(default, e))
        if CLIENT in e.roles and e.variant != DEFAULT_VARIANT:
            out.append(PairCase(e, default))
    return out


@dataclass
class Run:
    """One finished (or killed) adapter process."""

    role: str
    args: list[str]
    code: int | None  # None: still running at the deadline and killed by the test
    stdout: list[str]
    stderr: str
    exited_at: float | None  # time.monotonic() when the exit was seen
    group_left: bool  # a process of the adapter's process group outlived it

    def describe(self) -> str:
        return (
            f"{self.role} exit={self.code}\nargs: {self.args}\nstdout:\n"
            + "\n".join(self.stdout)
            + f"\nstderr (tail):\n{self.stderr[-3000:]}"
        )

    @property
    def result(self) -> dict[str, Any]:
        return json.loads(self.stdout[-1])


class Adapter:
    """An adapter process in its own process group, as the runner starts it."""

    def __init__(self, role: str, args: list[str], stderr_path: Path) -> None:
        self.role = role
        self.args = args
        self._stderr_path = stderr_path
        self._lines: list[str] = []
        self._cond = threading.Condition()
        self._eof = False
        self.exited_at: float | None = None
        with open(stderr_path, "wb") as err:
            self.proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=err,
                start_new_session=True,
            )
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            with self._cond:
                self._lines.append(raw.decode("utf-8", "replace").rstrip("\n"))
                self._cond.notify_all()
        with self._cond:
            self._eof = True
            self._cond.notify_all()

    @property
    def stdout_closed(self) -> bool:
        with self._cond:
            return self._eof

    def first_line(self, timeout: float) -> str | None:
        with self._cond:
            self._cond.wait_for(lambda: self._lines or self._eof, timeout)
            return self._lines[0] if self._lines else None

    def wait(self, timeout: float) -> bool:
        try:
            self.proc.wait(timeout=max(0.0, timeout))
        except subprocess.TimeoutExpired:
            return False
        if self.exited_at is None:
            self.exited_at = time.monotonic()
        return True

    def finish(self, timeout: float = 0.0) -> Run:
        """Wait up to timeout, then kill the group; idempotent."""
        exited = self.wait(timeout)
        group_left = exited and _group_alive(self.proc.pid)
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait()
        self._reader.join(5.0)
        assert not self._reader.is_alive(), f"{self.role}: stdout still open after the kill"
        assert self.proc.stdout is not None
        self.proc.stdout.close()
        with self._cond:
            lines = list(self._lines)
        return Run(
            role=self.role,
            args=self.args,
            code=self.proc.returncode if exited else None,
            stdout=lines,
            stderr=self._stderr_path.read_text(errors="replace"),
            exited_at=self.exited_at,
            group_left=group_left,
        )


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def render(opts: Options, form: str) -> list[str]:
    """--opt=value (the runner's form) or --opt value."""
    if form == "equals":
        return [f"--{k}={v}" for k, v in opts]
    return [a for k, v in opts for a in (f"--{k}", v)]


@dataclass
class Pair:
    client: Run | None  # None: the server never became ready
    server: Run
    trace: list[Any]  # Datagrams, or Segments with --transport=tls
    t0: float  # time.monotonic() at proxy start; trace times are relative to it

    @property
    def wire(self) -> Wire:
        return Wire.of(self.trace)


class Harness:
    """Starts adapters with every option of their role and cleans up after the test."""

    def __init__(self, pki: TestPki, tmp_path: Path) -> None:
        self.pki = pki
        self.tmp_path = tmp_path
        self._adapters: list[Adapter] = []

    def options(self, impl: Implementation, role: str, **overrides: str | None) -> Options:
        """The baseline: a valid X25519 configuration; a None override drops the option."""
        opts = {
            "role": role,
            "variant": impl.variant,
            "host": HOST,
            "port": "0" if role == SERVER else str(UNUSED_PORT),
            "groups": X25519,
            "transport": "dtls",
            "resume": "off",
            "mtu": "1500",
            "ca": str(self.pki.ca_cert),
        }
        if role == SERVER:
            opts |= {"validate": "off", "cert": str(self.pki.server_cert)}
            opts["key"] = str(self.pki.server_key)
        else:
            opts["key-share"] = X25519
        for k, v in overrides.items():
            opts[k.replace("_", "-")] = v
        return [(k, v) for k, v in opts.items() if v is not None]

    def start(self, impl: Implementation, role: str, args: list[str]) -> Adapter:
        path = self.tmp_path / f"{len(self._adapters):02d}-{role}.stderr"
        adapter = Adapter(role, [str(impl.adapter), *args], path)
        self._adapters.append(adapter)
        return adapter

    def run(self, impl: Implementation, role: str, args: list[str], timeout: float) -> Run:
        return self.start(impl, role, args).finish(timeout)

    def pair(
        self,
        case: PairCase,
        *,
        client: dict[str, str | None] | None = None,
        server: dict[str, str | None] | None = None,
        rules: Sequence[Rule] = (),
        form: str = "equals",
        client_may_be_unsupported: bool = False,
    ) -> Pair:
        """Server, then a proxy without PMTU limit (sizes are checked on the trace), then client.
        Skips when a side exits 2, unless the caller checks an unsupported client itself.
        With --transport=tls the proxy is the runner's TCP relay.
        """
        sopts = self.options(case.server, SERVER, **(server or {}))
        srv = self.start(case.server, SERVER, render(sopts, form))
        port = await_ready(srv)
        tls = dict(sopts)["transport"] == "tls"
        proxy_cm = TcpProxy((HOST, port)) if tls else UdpProxy((HOST, port), pmtu=None, rules=rules)
        with proxy_cm as proxy:
            t0 = time.monotonic()
            copts = self.options(case.client, CLIENT, port=str(proxy.address[1]), **(client or {}))
            cli = self.start(case.client, CLIENT, render(copts, form))
            if cli.wait(RUN_TIMEOUT):
                srv.wait(SERVER_GRACE)
            client_run, server_run = cli.finish(), srv.finish()
        for run in (server_run, client_run):
            if unsupported(run) and not (run is client_run and client_may_be_unsupported):
                check_protocol(run)
                pytest.skip(f"{run.role} reports unsupported: {run.result['error']}")
        return Pair(client_run, server_run, proxy.trace, t0)

    def close(self) -> None:
        for adapter in self._adapters:
            if adapter.proc.returncode is None:
                adapter.finish()


def await_ready(server: Adapter) -> int:
    """The port from the server's ready line; an exit 2 before it skips, anything else fails."""
    line = server.first_line(READY_TIMEOUT)
    port = ready_port(line)
    if port is not None:
        return port
    run = server.finish(SERVER_GRACE if line is not None or server.stdout_closed else 0.0)
    if run.code == EXIT_UNSUPPORTED:
        check_protocol(run)
        pytest.skip(f"server reports unsupported: {run.result['error']}")
    if run.code is None:
        reason = f"no ready line within {READY_TIMEOUT} s (first line {line!r})"
    elif run.code == EXIT_USAGE:
        reason = "the server rejected its options (exit 64) instead of printing ready"
    else:
        reason = f"the server exited {run.code} before printing ready"
    pytest.fail(f"{reason}\n{run.describe()}", pytrace=False)


def ready_port(line: str | None) -> int | None:
    try:
        event = json.loads(line or "")
    except json.JSONDecodeError:
        return None
    port = event.get("port") if isinstance(event, dict) else None
    if event.get("event") != "ready" or not isinstance(port, int) or isinstance(port, bool):
        return None
    return port if 0 < port < 65536 else None


def check_protocol(run: Run | None) -> dict[str, Any]:
    """Every rule of "Output protocol" and "Exit codes"; returns the result line."""
    assert run is not None, "the client never started"
    ctx = run.describe()
    assert run.code is not None, f"{run.role} did not exit in time\n{ctx}"
    assert not run.group_left, f"{run.role} left a process in its process group\n{ctx}"
    events = []
    for line in run.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            raise AssertionError(f"stdout line is not JSON: {line!r}\n{ctx}") from None
        assert isinstance(event, dict) and isinstance(event.get("event"), str), ctx
        events.append(event)
    kinds = [e["event"] for e in events]
    allowed = (["result"], ["ready", "result"]) if run.role == SERVER else (["result"],)
    assert kinds in allowed, f"stdout events {kinds}, expected one of {allowed}\n{ctx}"
    if kinds[0] == "ready":
        assert events[0].keys() == {"event", "port"}, ctx
        assert ready_port(run.stdout[0]) is not None, ctx
    result = events[-1]
    assert result.keys() == RESULT_KEYS, f"result keys {sorted(result)}\n{ctx}"
    assert isinstance(result["ok"], bool), ctx
    for key in ("version", "group", "error"):
        assert result[key] is None or isinstance(result[key], str), f"{key}\n{ctx}"
    for key in ("hrr", "hrr_cookie", "hrr_group", "resumed"):
        assert result[key] is None or isinstance(result[key], bool), f"{key}\n{ctx}"
    assert run.code in (EXIT_OK, EXIT_FAIL, EXIT_UNSUPPORTED, EXIT_USAGE), ctx
    assert result["ok"] is (run.code == EXIT_OK), f"ok contradicts the exit code\n{ctx}"
    if run.code == EXIT_OK:
        assert result["error"] is None, ctx
    else:
        assert isinstance(result["error"], str) and result["error"].strip(), ctx
    if run.code in (EXIT_UNSUPPORTED, EXIT_USAGE):
        nulls = {k: result[k] for k in HANDSHAKE_KEYS}
        assert nulls == dict.fromkeys(HANDSHAKE_KEYS), f"must be null before the handshake\n{ctx}"
    if result["hrr"] is False:
        assert (result["hrr_cookie"], result["hrr_group"]) == (False, False), ctx
    # The runner's own validation must agree.
    assert parse_result_line(run.stdout)[1] is None, ctx
    return result


def check_ok(
    run: Run | None,
    group: str,
    *,
    hrr: bool,
    cookie: bool,
    hrr_group: bool,
    transport: str = "dtls",
    resumed: bool = False,
) -> None:
    result = check_protocol(run)
    expected = {"event": "result", "ok": True, "version": VERSIONS[transport], "group": group}
    expected |= {"hrr": hrr, "hrr_cookie": cookie, "hrr_group": hrr_group}
    expected |= {"resumed": resumed, "error": None}
    assert result == expected, run.describe() if run else ""


def check_pair_ok(
    pair: Pair, group: str, *, hrr: bool, hrr_group: bool, cookie: bool | None = None
) -> None:
    """Both sides succeed with the expected result, and the wire shows the same handshake.
    cookie=None (--validate=off): an HRR needed for the group may carry a library-forced cookie."""
    cookie = check_hrr_on_wire(pair, cookie)
    for run in (pair.client, pair.server):
        check_ok(run, group, hrr=hrr, cookie=cookie, hrr_group=hrr_group)
    wire = pair.wire
    assert wire.group == GROUP_CODES[group], wire
    assert (wire.hrr is not None) is hrr, wire


def check_hrr_on_wire(pair: Pair, cookie: bool | None = None) -> bool:
    """Both result lines report the HRR the trace shows; returns whether it had a cookie.
    cookie=None (--validate=off): no HRR that only carries a cookie."""
    hrr = pair.wire.hrr
    wire_cookie = hrr is not None and hrr.cookie
    if cookie is None:
        assert not (wire_cookie and hrr.selected_group is None), f"cookie-only HRR: {pair.wire}"
    else:
        assert wire_cookie is cookie, pair.wire
    seen = {"hrr": hrr is not None, "hrr_cookie": wire_cookie}
    seen["hrr_group"] = hrr is not None and hrr.selected_group is not None
    for run in (pair.client, pair.server):
        result = check_protocol(run)
        assert {k: result[k] for k in seen} == seen, f"{pair.wire}\n{run and run.describe()}"
    return wire_cookie


def check_hrr_per_flow(pair: Pair, cookie: bool | None = None) -> list[FlowHellos]:
    """check_hrr_on_wire for UDP or TCP traces with one flow per connection (--resume=ticket).
    Every flow must match cookie; the result lines describe the last flow."""
    flows = trace_flows(pair.trace)
    assert flows, f"no flows in the trace: {pair.trace!r}"
    for f in flows:
        wire_cookie = f.hrr is not None and f.hrr.cookie
        if cookie is None:
            assert not (wire_cookie and f.hrr.selected_group is None), f"cookie-only HRR: {f}"
        else:
            assert wire_cookie is cookie, f
    last = flows[-1].hrr
    seen = {"hrr": last is not None, "hrr_cookie": last is not None and last.cookie}
    seen["hrr_group"] = last is not None and last.selected_group is not None
    for run in (pair.client, pair.server):
        result = check_protocol(run)
        assert {k: result[k] for k in seen} == seen, f"{flows}\n{run and run.describe()}"
    return flows


def unsupported(run: Run | None) -> bool:
    return run is not None and run.code == EXIT_UNSUPPORTED


# --- Trace analysis ---------------------------------------------------------------------------

AEAD_TAG = 16  # every TLS 1.3 AEAD the adapters negotiate except the unused *_CCM_8 suites
# DTLSInnerPlaintext without padding: content + 1-byte type; ping/pong are 4 bytes, an alert 2.
APP_INNER, ALERT_INNER = 4 + 1, 2 + 1
APPLICATION_EPOCH = 3


@dataclass(frozen=True)
class Wire:
    """The plaintext handshake as the adapters sent it (one message per msg_type and seq)."""

    client_hellos: tuple[HelloInfo, ...]  # in message_seq order: CH1, CH2
    hrr: HelloInfo | None
    group: int | None  # key_share group of the ServerHello that is not an HRR

    @classmethod
    def of(cls, trace: Sequence[Datagram]) -> Wire:
        fragments: dict[tuple[str, int, int, int], list[HandshakeFragment]] = defaultdict(list)
        for d in sent(trace):
            for f in parse_datagram(d.payload).handshake_fragments():
                if f.msg_type in (HS_CLIENT_HELLO, HS_SERVER_HELLO):
                    fragments[(d.direction, f.msg_type, f.message_seq, f.length)].append(f)
        hellos, hrr, group = [], None, None
        for (direction, msg_type, _, _), frags in sorted(fragments.items()):
            body = reassemble(frags)
            if body is None:
                continue
            if direction == "c2s" and msg_type == HS_CLIENT_HELLO:
                info = parse_hello(msg_type, body)
                assert info is not None
                hellos.append(info)
            elif direction == "s2c" and msg_type == HS_SERVER_HELLO:
                if body[2:34] == HRR_RANDOM:
                    hrr = parse_hello(msg_type, body)
                else:
                    group = server_hello_group(body)
        return cls(tuple(hellos), hrr, group)


def server_hello_group(body: bytes) -> int | None:
    """key_share group of a ServerHello body (RFC 9846 sec 4.2.3 layout)."""
    pos = 2 + 32
    pos += 1 + body[pos] + 2 + 1  # legacy_session_id_echo, cipher_suite, compression
    end = pos + 2 + int.from_bytes(body[pos : pos + 2])
    pos += 2
    while pos + 4 <= end:
        ext_type, ext_len = (
            int.from_bytes(body[pos : pos + 2]),
            int.from_bytes(body[pos + 2 : pos + 4]),
        )
        if ext_type == 51 and ext_len >= 2:
            return int.from_bytes(body[pos + 4 : pos + 6])
        pos += 4 + ext_len
    return None


def sent(trace: Sequence[Datagram]) -> Iterator[Datagram]:
    """Datagrams as the adapters sent them, whatever the proxy did with them."""
    return (d for d in trace if d.origin is None)


def datagram_sizes(trace: Sequence[Datagram], direction: str) -> list[int]:
    return [d.size for d in sent(trace) if d.direction == direction]


def application_records(parsed: ParsedDatagram) -> list[int]:
    """Inner plaintext lengths of the epoch-3 records in a datagram."""
    return [
        r.length - AEAD_TAG
        for r in parsed.records
        if isinstance(r, CiphertextRecord) and r.epoch_bits == APPLICATION_EPOCH
    ]


@dataclass(frozen=True)
class Event:
    index: int
    time: float
    direction: str
    kind: str  # "app" (ping/pong) or "alert"


def teardown_events(trace: Sequence[Datagram]) -> list[Event]:
    """ping, pong and alerts, told apart from ACKs and tickets by their encrypted length."""
    kinds = {APP_INNER: "app", ALERT_INNER: "alert"}
    return [
        Event(d.index, d.time, d.direction, kinds[n])
        for d in sent(trace)
        for n in application_records(parse_datagram(d.payload))
        if n in kinds
    ]


@dataclass
class DropAlerts(Rule):
    """Drop every datagram in one direction that carries an application-epoch alert."""

    direction: str
    dropped: int = field(default=0)

    def on_packet(self, packet: Packet, now: float) -> Verdict:
        if packet.direction == self.direction and ALERT_INNER in application_records(packet.parsed):
            self.dropped += 1
            return drop("close_notify")
        return FORWARD


def port_is_bound(port: int) -> bool:
    """True if a UDP socket already holds HOST:port (no SO_REUSEADDR here, so bind fails)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((HOST, port))
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                return True
            raise
    return False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]
