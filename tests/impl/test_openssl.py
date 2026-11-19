"""OpenSSL adapter self-interop on loopback, without the proxy (real builds, real UDP sockets)."""

from __future__ import annotations

import json
import re
import select
import subprocess
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
            "variant": self.variant,
            "host": HOST,
            "port": str(port),
            "groups": "X25519",
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
                proc.wait()


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


def _assert_ok(run: Run, group: str, hrr: bool, cookie: bool = False, hrr_group: bool = False):
    expected = {"event": "result", "ok": True, "version": "DTLSv1.3", "group": group}
    expected |= {"hrr": hrr, "hrr_cookie": cookie, "hrr_group": hrr_group, "error": None}
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
    expected |= {"hrr_cookie": None, "hrr_group": None, "error": run.result["error"]}
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
        "share-not-in-groups": {"key_share": MLKEM},
        "empty-group": {"groups": "X25519,,X448"},
    },
    "server": {
        "missing-validate": {"validate": None},
        "missing-mtu": {"mtu": None},
        "missing-key": {"key": None},
        "client-option": {"key_share": "default"},
        "bad-validate": {"validate": "maybe"},
        "bad-port": {"port": "70000"},
        "bad-mtu": {"mtu": "48"},
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
