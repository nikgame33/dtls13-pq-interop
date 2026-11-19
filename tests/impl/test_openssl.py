"""OpenSSL adapter self-interop on loopback, without the proxy (real builds, real UDP sockets)."""

from __future__ import annotations

import json
import re
import select
import socket
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from dtls_interop import pki

TIMEOUT = 20.0
HOST = "127.0.0.1"
IP_UDP_OVERHEAD = 48  # --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers


@dataclass
class Run:
    code: int
    result: dict
    stderr: str


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert lines, "adapter printed no JSON line"
    assert lines[-1]["event"] == "result", lines
    return lines[-1]


class Adapters:
    """Starts adapter processes and kills any left over at teardown."""

    def __init__(self, adapter: Path, test_pki: pki.TestPki, tmp_path: Path) -> None:
        self.adapter = adapter
        self.pki = test_pki
        self.tmp_path = tmp_path
        self.port = _free_udp_port()
        self.procs: list[subprocess.Popen[str]] = []

    def _args(self, role: str, groups: str, extra: list[str]) -> list[str]:
        """Same --opt=value syntax and role-specific flags as the runner."""
        args = [str(self.adapter), f"--role={role}", f"--host={HOST}", f"--port={self.port}"]
        args += [f"--groups={groups}", *extra, f"--ca={self.pki.ca_cert}"]
        if role == "server":
            return [*args, f"--cert={self.pki.server_cert}", f"--key={self.pki.server_key}"]
        return args

    def start_server(self, groups: str, *extra: str, cert: pki.TestPki | None = None) -> Server:
        args = self._args("server", groups, list(extra))
        if cert is not None:
            args += [f"--cert={cert.server_cert}", f"--key={cert.server_key}"]
        stderr = self.tmp_path / f"server-{len(self.procs)}.log"
        with stderr.open("w") as err:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, text=True)
        self.procs.append(proc)
        server = Server(proc, stderr)
        server.wait_ready()
        return server

    def run_client(self, groups: str, *extra: str) -> Run:
        proc = subprocess.run(
            self._args("client", groups, list(extra)),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        return Run(proc.returncode, _result(proc.stdout), proc.stderr)

    def kill_all(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


@dataclass
class Server:
    proc: subprocess.Popen[str]
    stderr: Path

    def wait_ready(self) -> None:
        assert self.proc.stdout is not None
        readable, _, _ = select.select([self.proc.stdout], [], [], TIMEOUT)
        assert readable, "server did not print a ready line in time"
        line = self.proc.stdout.readline()
        assert line, f"server exited before ready:\n{self.stderr.read_text()}"
        assert json.loads(line) == {"event": "ready"}, line

    def finish(self) -> Run:
        stdout, _ = self.proc.communicate(timeout=TIMEOUT)
        return Run(self.proc.returncode, _result(stdout), self.stderr.read_text())


@pytest.fixture
def adapters(require_impl, test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Adapters]:
    a = Adapters(require_impl("openssl").adapter, test_pki, tmp_path)
    yield a
    a.kill_all()


def _handshake(
    adapters: Adapters, server_groups: str, client_groups: str, *, server: list, client: list
) -> tuple[Run, Run]:
    srv = adapters.start_server(server_groups, *server)
    cli = adapters.run_client(client_groups, *client)
    return cli, srv.finish()


def _assert_ok(run: Run, group: str, hrr: bool) -> None:
    expected = {"event": "result", "ok": True, "version": "DTLSv1.3", "group": group}
    expected |= {"hrr": hrr, "error": None}
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
    """S01: X25519, full share, PMTU 1500, no validation; options given as "--opt value"."""
    common = ["--mtu", "1500"]
    cli, srv = _handshake(
        adapters,
        "X25519",
        "X25519",
        server=[*common, "--validate", "off"],
        client=[*common, "--key-share", "X25519"],
    )
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv, "X25519", hrr=False)


@pytest.mark.parametrize("mtu", [1500, 1280], ids=["S02-unfragmented", "S03-fragmented-CH1"])
def test_x25519mlkem768_self_interop(adapters: Adapters, mtu: int) -> None:
    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768",
        "X25519MLKEM768",
        server=[f"--mtu={mtu}", "--validate=off"],
        client=[f"--mtu={mtu}", "--key-share=X25519MLKEM768"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=False)
    _assert_ok(srv, "X25519MLKEM768", hrr=False)
    assert cli.stderr.count(">> ClientHello") == 1, cli.stderr
    # The CH1 record is 1422 bytes: one datagram within 1452 (1500 - 48), two within 1232.
    assert _ch_records(srv) == (1 if mtu == 1500 else 2), srv.stderr
    _assert_fits(cli, mtu)
    _assert_fits(srv, mtu)


@pytest.mark.parametrize("mtu", [1500, 1280], ids=["unfragmented", "S04-fragmented-CH1"])
def test_cookie_validation_x25519mlkem768(adapters: Adapters, mtu: int) -> None:
    """The listener's stateless HRR cookie is a real HRR, so both sides report hrr=true."""
    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768",
        "X25519MLKEM768",
        server=[f"--mtu={mtu}", "--validate=cookie"],
        client=[f"--mtu={mtu}", "--key-share=X25519MLKEM768"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv, "X25519MLKEM768", hrr=True)
    assert cli.stderr.count(">> ClientHello") == 2, cli.stderr
    # The 140-byte cookie grows CH2 to about 1555 bytes, so CH2 is fragmented even at 1500.
    assert _ch_records(srv) == (1 + 2 if mtu == 1500 else 2 + 2), srv.stderr
    _assert_fits(cli, mtu)
    _assert_fits(srv, mtu)


def test_wrong_guess_triggers_hrr(adapters: Adapters) -> None:
    """S06: client shares X25519, server only accepts the hybrid."""
    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768",
        "X25519MLKEM768,X25519",
        server=["--mtu=1280", "--validate=off"],
        client=["--mtu=1280", "--key-share=X25519"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv, "X25519MLKEM768", hrr=True)


def test_server_preference_order(adapters: Adapters) -> None:
    """--groups is a strict server preference: the client's share is not enough to avoid HRR."""
    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768,X25519",
        "X25519,X25519MLKEM768",
        server=["--mtu=1500", "--validate=off"],
        client=["--mtu=1500", "--key-share=X25519"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv, "X25519MLKEM768", hrr=True)


def test_listener_default_mtu_is_minimum(adapters: Adapters) -> None:
    """Without --mtu, IP_MTU fails on the unconnected listener socket and OpenSSL falls back to
    its 256-byte link minimum, so the ServerHello is cut into 214-byte records."""
    cli, srv = _handshake(
        adapters, "X25519MLKEM768", "X25519MLKEM768", server=["--validate=off"], client=[]
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=False)
    _assert_ok(srv, "X25519MLKEM768", hrr=False)
    sent = [line for line in srv.stderr.splitlines() if line.startswith(">> plaintext")]
    assert sent == [">> plaintext handshake record (214 bytes)"] * 5 + [
        ">> plaintext handshake record (176 bytes)"
    ], srv.stderr
    assert max(_datagrams(srv)) == 228, srv.stderr


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="OpenSSL 4.1.0 clients cannot send an empty key_share: tls_construct_ctos_key_share "
    "fails with NO_SUITABLE_KEY_SHARE unless at least one share is added, so the adapter exits 2",
)
def test_empty_key_share_triggers_hrr(adapters: Adapters) -> None:
    """S05 with an OpenSSL client; the client is checked first so the xfail does not wait."""
    srv = adapters.start_server("X25519MLKEM768", "--mtu=1500", "--validate=off")
    cli = adapters.run_client("X25519MLKEM768", "--mtu=1500", "--key-share=empty")
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv.finish(), "X25519MLKEM768", hrr=True)


def test_empty_key_share_reported_unsupported(adapters: Adapters) -> None:
    cli = adapters.run_client("X25519MLKEM768", "--key-share=empty")
    assert cli.code == 2, cli.stderr
    assert cli.result["ok"] is False
    assert "empty key_share" in cli.result["error"]


@pytest.mark.parametrize("role", ["client", "server"])
def test_unimplemented_group_is_unsupported(adapters: Adapters, role: str) -> None:
    """MLKEM512X25519 (draft-rosomakho-tls-ecdhe-mlkem512) is not in OpenSSL 4.1.0."""
    args = adapters._args(role, "MLKEM512X25519,X25519", ["--mtu=1280"])
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    result = _result(proc.stdout)
    assert proc.returncode == 2, proc.stderr
    assert result == {
        "event": "result",
        "ok": False,
        "version": None,
        "group": None,
        "hrr": None,
        "error": result["error"],
    }
    assert "MLKEM512X25519" in result["error"]
    assert '"ready"' not in proc.stdout


@pytest.mark.parametrize("role", ["client", "server"])
def test_mtu_below_library_minimum_is_unsupported(adapters: Adapters, role: str) -> None:
    """--mtu=200 leaves 152 bytes of payload, below what SSL_set_mtu accepts."""
    args = adapters._args(role, "X25519", ["--mtu=200"])
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    assert proc.returncode == 2, proc.stderr
    assert "--mtu 200 rejected" in _result(proc.stdout)["error"]


def test_client_rejects_untrusted_server(adapters: Adapters, tmp_path: Path) -> None:
    other = pki.generate(tmp_path / "other-pki")
    srv = adapters.start_server("X25519", "--mtu=1500", cert=other)
    cli = adapters.run_client("X25519", "--mtu=1500")
    assert cli.code == 1, cli.stderr
    assert cli.result["ok"] is False
    assert "certificate verify failed" in cli.result["error"]
    assert srv.finish().code == 1


def test_psk_resumption_after_hrr(adapters: Adapters, tmp_path: Path) -> None:
    """S10-like: ticket from a cookie-validated handshake at MTU 1280, resumed in a new process."""
    keys, session = tmp_path / "ticket-keys.bin", tmp_path / "session.pem"
    server = ["--mtu=1280", "--validate=cookie"]
    client = ["--mtu=1280", "--key-share=X25519MLKEM768"]
    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768",
        "X25519MLKEM768",
        server=[*server, f"--psk-out={keys}"],
        client=[*client, f"--psk-out={session}"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv, "X25519MLKEM768", hrr=True)
    assert "resumed=0" in cli.stderr

    cli, srv = _handshake(
        adapters,
        "X25519MLKEM768",
        "X25519MLKEM768",
        server=[*server, f"--psk-in={keys}"],
        client=[*client, f"--psk-in={session}"],
    )
    _assert_ok(cli, "X25519MLKEM768", hrr=True)
    _assert_ok(srv, "X25519MLKEM768", hrr=True)
    assert "resumed=1" in cli.stderr
    assert "resumed=1" in srv.stderr
