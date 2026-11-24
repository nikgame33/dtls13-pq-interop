"""OpenSSL adapter self-interop on loopback, without the proxy (real builds, UDP/TCP sockets)."""

from __future__ import annotations

import json
import re
import select
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from dtls_interop import pki

TIMEOUT = 20.0
HOST = "127.0.0.1"
IP_UDP_OVERHEAD = 48  # --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers
VARIANTS = ["default", "accept"]
MLKEM = "X25519MLKEM768"


@dataclass
class Run:
    code: int
    result: dict
    stderr: str


def _result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert lines, "adapter printed no JSON line"
    assert lines[-1]["event"] == "result", lines
    return lines[-1]


@dataclass
class Server:
    proc: subprocess.Popen[str]
    stderr: Path
    port: int = 0

    def wait_ready(self) -> None:
        assert self.proc.stdout is not None
        readable, _, _ = select.select([self.proc.stdout], [], [], TIMEOUT)
        assert readable, "server did not print a ready line in time"
        line = self.proc.stdout.readline()
        assert line, f"server exited before ready:\n{self.stderr.read_text()}"
        ready = json.loads(line)
        assert ready.keys() == {"event", "port"} and ready["event"] == "ready", line
        assert 0 < ready["port"] < 65536, line
        self.port = ready["port"]

    def finish(self) -> Run:
        stdout, _ = self.proc.communicate(timeout=TIMEOUT)
        return Run(self.proc.returncode, _result(stdout), self.stderr.read_text())


class Adapters:
    """Starts adapter processes with the full option set and kills leftovers at teardown."""

    def __init__(self, adapter: Path, test_pki: pki.TestPki, tmp_path: Path, variant: str) -> None:
        self.adapter = adapter
        self.pki = test_pki
        self.tmp_path = tmp_path
        self.variant = variant
        self.procs: list[subprocess.Popen[str]] = []

    def args(self, role: str, port: int = 0, /, **opts: str | None) -> list[str]:
        """Every option of the role as --opt=value; a None override drops that option."""
        base: dict[str, str | None] = {
            "role": role,
            # Variants are server-only; the client always runs the default path.
            "variant": self.variant if role == "server" else "default",
            "host": HOST,
            "port": str(port),
            "groups": "X25519",
            "transport": "dtls",
            "resume": "off",
            "mtu": "1500",
            "ca": str(self.pki.ca_cert),
        }
        if role == "server":
            base |= {"validate": "off", "cert": str(self.pki.server_cert)}
            base |= {"key": str(self.pki.server_key)}
        else:
            base["key-share"] = "default"
        base |= {k.replace("_", "-"): v for k, v in opts.items()}
        return [str(self.adapter)] + [f"--{k}={v}" for k, v in base.items() if v is not None]

    def start_server(self, **opts: str | None) -> Server:
        stderr = self.tmp_path / f"server-{len(self.procs)}.log"
        with stderr.open("w") as err:
            proc = subprocess.Popen(
                self.args("server", **opts), stdout=subprocess.PIPE, stderr=err, text=True
            )
        self.procs.append(proc)
        server = Server(proc, stderr)
        server.wait_ready()
        return server

    def run_client(self, server: Server, **opts: str | None) -> Run:
        return self.run(self.args("client", server.port, **opts))

    def run(self, args: list[str]) -> Run:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
        return Run(proc.returncode, _result(proc.stdout), proc.stderr)

    def kill_all(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            # Popen's context exit waits and closes stdout, which finish() may not have read.
            with proc:
                pass


@pytest.fixture(params=VARIANTS)
def adapters(request, require_impl, test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Adapters]:
    a = Adapters(require_impl("openssl").adapter, test_pki, tmp_path, request.param)
    yield a
    a.kill_all()


@pytest.fixture
def listener(require_impl, test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Adapters]:
    """Only the default variant, for listener-specific behaviour."""
    a = Adapters(require_impl("openssl").adapter, test_pki, tmp_path, "default")
    yield a
    a.kill_all()


def _handshake(adapters: Adapters, server: dict, client: dict) -> tuple[Run, Run]:
    srv = adapters.start_server(**server)
    cli = adapters.run_client(srv, **client)
    return cli, srv.finish()


def _assert_ok(
    run: Run,
    group: str,
    hrr: bool,
    cookie: bool = False,
    hrr_group: bool = False,
    resumed: bool = False,
    version: str = "DTLSv1.3",
) -> None:
    expected = {"event": "result", "ok": True, "version": version, "group": group}
    expected |= {"hrr": hrr, "hrr_cookie": cookie, "hrr_group": hrr_group}
    expected |= {"resumed": resumed, "error": None}
    assert (run.code, run.result) == (0, expected), run.stderr


def _ch_records(server: Run) -> int:
    """Plaintext handshake records the server received, i.e. ClientHello fragments."""
    return server.stderr.count("<< plaintext handshake record")


def _datagrams(run: Run) -> list[int]:
    """Sizes of all UDP datagrams the adapter sent."""
    return [int(n) for n in re.findall(r"^>> datagram \((\d+) bytes\)$", run.stderr, re.M)]


def _assert_fits(run: Run, mtu: int) -> None:
    sizes = _datagrams(run)
    assert sizes, run.stderr
    assert max(sizes) <= mtu - IP_UDP_OVERHEAD, sizes


def test_x25519_self_interop(adapters: Adapters) -> None:
    """S01; options given as "--opt value"; both sides see the peer's close_notify."""
    srv = adapters.start_server(groups="X25519")
    args = adapters.args("client", srv.port, groups="X25519", key_share="X25519")
    cli = adapters.run([a for arg in args for a in arg.split("=", 1)])
    srv_run = srv.finish()
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv_run, "X25519", hrr=False)
    for run in (cli, srv_run):
        assert "<< alert close notify" in run.stderr, run.stderr
        assert "no close_notify" not in run.stderr, run.stderr


@pytest.mark.parametrize("mtu", [1500, 1280], ids=["S02-unfragmented", "S03-fragmented-CH1"])
def test_x25519mlkem768_self_interop(adapters: Adapters, mtu: int) -> None:
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": str(mtu)},
        client={"groups": MLKEM, "mtu": str(mtu), "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert cli.stderr.count(">> ClientHello") == 1, cli.stderr
    # The CH1 record is 1422 bytes: one datagram within 1452 (1500 - 48), two within 1232.
    assert _ch_records(srv) == (1 if mtu == 1500 else 2), srv.stderr
    _assert_fits(cli, mtu)
    _assert_fits(srv, mtu)


@pytest.mark.parametrize("mtu", [1500, 1280], ids=["unfragmented", "S04-fragmented-CH1"])
def test_cookie_validation_x25519mlkem768(adapters: Adapters, mtu: int) -> None:
    """A validation-only HRR carries a cookie but no selected_group."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": str(mtu), "validate": "cookie"},
        client={"groups": MLKEM, "mtu": str(mtu), "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True)
    assert cli.stderr.count(">> ClientHello") == 2, cli.stderr
    # The cookie grows CH2 to over 1540 bytes, so CH2 is fragmented even at 1500.
    assert _ch_records(srv) == (1 + 2 if mtu == 1500 else 2 + 2), srv.stderr
    _assert_fits(cli, mtu)
    _assert_fits(srv, mtu)


def test_cookie_and_wrong_guess_share_one_hrr(adapters: Adapters) -> None:
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "1280", "validate": "cookie"},
        client={"groups": f"{MLKEM},X25519", "mtu": "1280", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True, hrr_group=True)
    assert cli.stderr.count(">> ClientHello") == 2, cli.stderr


def test_wrong_guess_triggers_hrr(adapters: Adapters) -> None:
    """S06: client shares X25519, server only accepts the hybrid."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "1280"},
        client={"groups": f"{MLKEM},X25519", "mtu": "1280", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)


def test_acceptable_share_wins_over_server_preference(adapters: Adapters) -> None:
    """Contract rule 1 (key share first): no HRR just to get the server's preferred group."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"{MLKEM},X25519", "key_share": "X25519"},
    )
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv, "X25519", hrr=False)


def test_hrr_selects_highest_ranked_server_group(adapters: Adapters) -> None:
    """Contract rule 2: without a usable share, the HRR follows the server's order."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"secp256r1,X25519,{MLKEM}", "key_share": "secp256r1"},
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)


def test_no_mutual_group_fails(adapters: Adapters) -> None:
    """Contract rule 3."""
    cli, srv = _handshake(
        adapters, server={"groups": MLKEM}, client={"groups": "X25519", "key_share": "X25519"}
    )
    assert (cli.code, cli.result["ok"]) == (1, False), cli.stderr
    assert (srv.code, srv.result["ok"]) == (1, False), srv.stderr
    assert "no suitable key share" in srv.result["error"]


def test_listener_default_mtu_is_minimum(listener: Adapters) -> None:
    """--mtu=default: IP_MTU fails on the unconnected listener socket and OpenSSL falls back to
    its 256-byte link minimum, so the ServerHello is cut into 214-byte records."""
    cli, srv = _handshake(
        listener,
        server={"groups": MLKEM, "mtu": "default"},
        client={"groups": MLKEM, "mtu": "default"},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    sent = [line for line in srv.stderr.splitlines() if line.startswith(">> plaintext")]
    assert sent == [">> plaintext handshake record (214 bytes)"] * 5 + [
        ">> plaintext handshake record (176 bytes)"
    ], srv.stderr
    assert max(_datagrams(srv)) == 228, srv.stderr


def test_accept_variant_default_mtu_is_interface_mtu(require_impl, test_pki, tmp_path) -> None:
    """--mtu=default on a connected socket: IP_MTU of loopback, so nothing is fragmented."""
    a = Adapters(require_impl("openssl").adapter, test_pki, tmp_path, "accept")
    try:
        cli, srv = _handshake(
            a,
            server={"groups": MLKEM, "mtu": "default"},
            client={"groups": MLKEM, "mtu": "default"},
        )
    finally:
        a.kill_all()
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert _ch_records(srv) == 1, srv.stderr
    assert max(_datagrams(srv)) > 1500, srv.stderr


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="OpenSSL 4.1.0 clients cannot send an empty key_share: tls_construct_ctos_key_share "
    "fails with NO_SUITABLE_KEY_SHARE unless at least one share is added, so the adapter exits 2",
)
def test_empty_key_share_triggers_hrr(adapters: Adapters) -> None:
    """S05 with an OpenSSL client; the client is checked first so the xfail does not wait."""
    srv = adapters.start_server(groups=MLKEM)
    cli = adapters.run_client(srv, groups=MLKEM, key_share="empty")
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv.finish(), MLKEM, hrr=True, hrr_group=True)


def _assert_no_handshake(run: Run, code: int, error: str) -> None:
    expected = {"event": "result", "ok": False, "version": None, "group": None, "hrr": None}
    expected |= {"hrr_cookie": None, "hrr_group": None, "resumed": None}
    expected["error"] = run.result["error"]
    assert (run.code, run.result) == (code, expected), run.stderr
    assert error in run.result["error"], run.result


def test_empty_key_share_reported_unsupported(listener: Adapters) -> None:
    cli = listener.run(listener.args("client", 1, groups=MLKEM, key_share="empty"))
    _assert_no_handshake(cli, 2, "empty key_share")


@pytest.mark.parametrize("role", ["client", "server"])
def test_unimplemented_group_is_unsupported(listener: Adapters, role: str) -> None:
    """MLKEM512X25519 (draft-rosomakho-tls-ecdhe-mlkem512) is not in OpenSSL 4.1.0."""
    run = listener.run(listener.args(role, 1, groups="MLKEM512X25519,X25519"))
    _assert_no_handshake(run, 2, "MLKEM512X25519")


@pytest.mark.parametrize("role", ["client", "server"])
def test_mtu_below_library_minimum_is_unsupported(listener: Adapters, role: str) -> None:
    """--mtu=200 leaves 152 bytes of payload, below what SSL_set_mtu accepts."""
    run = listener.run(listener.args(role, 1, mtu="200"))
    _assert_no_handshake(run, 2, "--mtu=200 rejected")


USAGE_ERRORS = {
    "client": {
        "missing-key-share": {"key_share": None},
        "missing-ca": {"ca": None},
        "missing-variant": {"variant": None},
        "server-option": {"validate": "off"},
        "unknown-option": {"psk_out": "x"},
        "bad-mtu": {"mtu": "big"},
        "bad-port": {"port": "0"},
        "bad-variant": {"variant": "nope"},
        "server-variant": {"variant": "accept"},
        "share-not-in-groups": {"key_share": MLKEM},
        "empty-group": {"groups": "X25519,,X448"},
        "missing-transport": {"transport": None},
        "bad-transport": {"transport": "quic"},
        "missing-resume": {"resume": None},
        "bad-resume": {"resume": "psk"},
        "tls-numeric-mtu": {"transport": "tls", "mtu": "1500"},
    },
    "server": {
        "missing-validate": {"validate": None},
        "missing-mtu": {"mtu": None},
        "missing-key": {"key": None},
        "client-option": {"key_share": "default"},
        "bad-validate": {"validate": "maybe"},
        "bad-port": {"port": "70000"},
        "bad-mtu": {"mtu": "48"},
        "bad-variant": {"variant": "nope"},
        "missing-transport": {"transport": None},
        "bad-transport": {"transport": "TLS"},
        "missing-resume": {"resume": None},
        "bad-resume": {"resume": "on"},
        "tls-numeric-mtu": {"transport": "tls", "mtu": "1280"},
    },
}


@pytest.mark.parametrize(
    "role,opts",
    [(role, opts) for role, cases in USAGE_ERRORS.items() for opts in cases.values()],
    ids=[f"{role}-{name}" for role, cases in USAGE_ERRORS.items() for name in cases],
)
def test_usage_errors_exit_64(listener: Adapters, role: str, opts: dict) -> None:
    args = listener.args(role, 4433 if role == "client" else 0, **opts)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    assert '"ready"' not in proc.stdout
    _assert_no_handshake(Run(proc.returncode, _result(proc.stdout), proc.stderr), 64, "usage:")


def test_duplicate_option_is_usage_error(listener: Adapters) -> None:
    args = [*listener.args("client", 4433), "--mtu=1280"]
    _assert_no_handshake(listener.run(args), 64, "given twice")


def test_client_rejects_untrusted_server(adapters: Adapters, tmp_path: Path) -> None:
    other = pki.generate(tmp_path / "other-pki")
    srv = adapters.start_server(cert=str(other.server_cert), key=str(other.server_key))
    cli = adapters.run_client(srv)
    assert cli.code == 1, cli.stderr
    assert cli.result["ok"] is False
    assert "certificate verify failed" in cli.result["error"]
    assert srv.finish().code == 1


TLS = {"transport": "tls", "mtu": "default"}


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_tls_x25519_self_interop(listener: Adapters, validate: str) -> None:
    """TLS 1.3 over TCP; with cookie, SSL_stateless() answers CH1 with a cookie-only HRR."""
    cookie = validate == "cookie"
    cli, srv = _handshake(
        listener,
        server=TLS | {"validate": validate},
        client=TLS | {"key_share": "X25519"},
    )
    for run in (cli, srv):
        _assert_ok(run, "X25519", hrr=cookie, cookie=cookie, version="TLSv1.3")
        assert "<< alert close notify" in run.stderr, run.stderr
        assert ">> datagram" not in run.stderr, run.stderr
    assert cli.stderr.count(">> ClientHello") == (2 if cookie else 1), cli.stderr


def test_tls_cookie_and_wrong_guess_share_one_hrr(listener: Adapters) -> None:
    """The TLS HRR is parsed with its 4-byte handshake header, so selected_group is found too."""
    cli, srv = _handshake(
        listener,
        server=TLS | {"groups": MLKEM, "validate": "cookie"},
        client=TLS | {"groups": f"{MLKEM},X25519", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True, hrr_group=True, version="TLSv1.3")
    _assert_ok(srv, MLKEM, hrr=True, cookie=True, hrr_group=True, version="TLSv1.3")


def test_dtls_only_variant_with_tls_is_unsupported(require_impl, test_pki, tmp_path) -> None:
    a = Adapters(require_impl("openssl").adapter, test_pki, tmp_path, "accept")
    run = a.run(a.args("server", **TLS))
    _assert_no_handshake(run, 2, "DTLS only")


def _local_ports(client: Run) -> list[int]:
    return [int(p) for p in re.findall(r"^socket: local port (\d+)$", client.stderr, re.M)]


def _assert_resumed(cli: Run, srv: Run, group: str, cookie: bool, version: str) -> None:
    for run in (cli, srv):
        _assert_ok(run, group, hrr=cookie, cookie=cookie, resumed=True, version=version)
        assert run.stderr.count("handshake done:") == 2, run.stderr
    ports = _local_ports(cli)
    assert len(ports) == 2 and ports[0] != ports[1], cli.stderr
    # Connection 1 is a full handshake with a certificate; connection 2 resumes without one.
    assert srv.stderr.count(">> Certificate (") == 1, srv.stderr
    # A cookie HRR on each connection means two ClientHellos per connection.
    assert cli.stderr.count(">> ClientHello") == (4 if cookie else 2), cli.stderr


def test_s10_dtls_resumption_after_cookie(adapters: Adapters) -> None:
    """S10: connection 2 comes from a new port, gets a cookie HRR and still resumes."""
    common = {"groups": MLKEM, "mtu": "1280", "resume": "ticket"}
    cli, srv = _handshake(
        adapters,
        server=common | {"validate": "cookie"},
        client=common | {"key_share": MLKEM},
    )
    _assert_resumed(cli, srv, MLKEM, cookie=True, version="DTLSv1.3")
    _assert_fits(cli, 1280)
    _assert_fits(srv, 1280)


def test_dtls_resumption_without_validation(adapters: Adapters) -> None:
    cli, srv = _handshake(adapters, server={"resume": "ticket"}, client={"resume": "ticket"})
    _assert_resumed(cli, srv, "X25519", cookie=False, version="DTLSv1.3")


def test_tls_resumption_without_validation(listener: Adapters) -> None:
    ticket = TLS | {"resume": "ticket"}
    cli, srv = _handshake(listener, server=ticket, client=ticket)
    _assert_resumed(cli, srv, "X25519", cookie=False, version="TLSv1.3")


def test_tls_resumption_after_stateful_hrr(listener: Adapters) -> None:
    """A key-share HRR keeps the server's state, and the binder over CH1 + HRR verifies."""
    ticket = TLS | {"resume": "ticket", "groups": f"{MLKEM},X25519"}
    cli, srv = _handshake(
        listener,
        server=ticket | {"groups": MLKEM},
        client=ticket | {"key_share": "X25519"},
    )
    for run in (cli, srv):
        _assert_ok(run, MLKEM, hrr=True, hrr_group=True, resumed=True, version="TLSv1.3")


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="OpenSSL 4.1.0 SSL_stateless(): ssl_get_prev_session() checks the PSK binder before "
    "tls_parse_ctos_cookie() restores hello_retry_request=SSL_HRR_PENDING (SSL_clear reset it), "
    "so tls_psk_do_binder() hashes CH2 without CH1 + HRR and fails with binder does not verify",
)
def test_tls_resumption_after_cookie(listener: Adapters) -> None:
    ticket = TLS | {"resume": "ticket"}
    cli, srv = _handshake(
        listener,
        server=ticket | {"validate": "cookie"},
        client=ticket | {"key_share": "X25519"},
    )
    # Any other failure is not the known limitation and must not be absorbed by the xfail.
    if (
        srv.code != 0
        and srv.result["error"] != "connection 2: stateless HRR: binder does not verify"
    ):
        raise RuntimeError(f"unexpected server result {srv.result}:\n{srv.stderr}")
    _assert_resumed(cli, srv, "X25519", cookie=True, version="TLSv1.3")


def _serve_without_tickets(test_pki: pki.TestPki, listening: socket.socket) -> None:
    """A Python ssl (system OpenSSL) TLS 1.3 server that issues no NewSessionTicket."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(test_pki.server_cert, test_pki.server_key)
    ctx.num_tickets = 0
    conn, _ = listening.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        assert tls.recv(4) == b"ping"
        tls.sendall(b"pong")
        tls.unwrap()


def test_client_without_ticket_fails(listener: Adapters, test_pki: pki.TestPki) -> None:
    with socket.create_server((HOST, 0)) as listening:
        thread = threading.Thread(target=_serve_without_tickets, args=(test_pki, listening))
        thread.start()
        port = listening.getsockname()[1]
        cli = listener.run(listener.args("client", port, resume="ticket", **TLS))
        thread.join(TIMEOUT)
    expected = {"event": "result", "ok": False, "version": "TLSv1.3", "group": "X25519"}
    expected |= {"hrr": False, "hrr_cookie": False, "hrr_group": False, "resumed": False}
    expected["error"] = "connection 1: no session ticket received"
    assert (cli.code, cli.result) == (1, expected), cli.stderr
    assert len(_local_ports(cli)) == 1, cli.stderr


def test_resume_errors_name_the_connection(listener: Adapters) -> None:
    """With --resume=ticket an error before connection 1 is already prefixed."""
    run = listener.run(listener.args("client", 1, resume="ticket", groups="MLKEM512X25519"))
    _assert_no_handshake(run, 2, "MLKEM512X25519")
    assert run.result["error"].startswith("connection 1: "), run.result
