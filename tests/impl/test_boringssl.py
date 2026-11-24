"""BoringSSL adapter self-interop on loopback, without the proxy (real builds, real UDP sockets)."""

from __future__ import annotations

import json
import re
import select
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from dtls_interop import pki

TIMEOUT = 20.0
HANG_TIMEOUT = 8.0  # a dropped ClientHello is retransmitted, never failed; give up after this
HOST = "127.0.0.1"
IP_UDP_OVERHEAD = 48  # --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers
MLKEM = "X25519MLKEM768"
# ssl/d1_both.cc kDefaultMTU: the datagram size BoringSSL uses when nobody configures one.
BSSL_DEFAULT_DATAGRAM = 1500 - 28
# ssl/ssl_key_share.cc DefaultSupportedGroupIds.
BSSL_DEFAULT_GROUPS = f"{MLKEM},X25519,secp256r1,secp384r1"


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

    def __init__(self, adapter: Path, test_pki: pki.TestPki, tmp_path: Path) -> None:
        self.adapter = adapter
        self.pki = test_pki
        self.tmp_path = tmp_path
        self.procs: list[subprocess.Popen[str]] = []

    def args(self, role: str, port: int = 0, /, **opts: str | None) -> list[str]:
        """Every option of the role as --opt=value; a None override drops that option."""
        base: dict[str, str | None] = {
            "role": role,
            "variant": "default",
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

    def run(self, args: list[str], timeout: float = TIMEOUT) -> Run:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return Run(proc.returncode, _result(proc.stdout), proc.stderr)

    def kill_all(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill()
            # Popen's context exit waits and closes stdout, which finish() may not have read.
            with proc:
                pass


@pytest.fixture
def adapters(require_impl, test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Adapters]:
    """BoringSSL has no variants file, so the default variant is the only one."""
    a = Adapters(require_impl("boringssl").adapter, test_pki, tmp_path)
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


def _client_hellos(run: Run, direction: str) -> list[str]:
    """key_share groups of every complete ClientHello sent (>>) or received (<<)."""
    return re.findall(
        rf"^{direction} ClientHello \(\d+ bytes, key_share=(\S+)\)$", run.stderr, re.M
    )


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
    assert _client_hellos(srv_run, "<<") == ["X25519"], srv_run.stderr
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
    assert _client_hellos(srv, "<<") == [MLKEM], srv.stderr
    # CH1 is 1337 bytes (1362-byte datagram): one datagram within 1452 (1500 - 48), two in 1232.
    assert _ch_records(srv) == (1 if mtu == 1500 else 2), srv.stderr
    _assert_fits(cli, mtu)
    _assert_fits(srv, mtu)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="BoringSSL servers never send an HRR cookie: do_send_hello_retry_request in "
    "ssl/tls13_server.cc writes only supported_versions and key_share, and there is no API "
    "for stateless address validation, so the adapter exits 2 before it is ready",
)
@pytest.mark.parametrize("mtu", [1500, 1280], ids=["unfragmented", "S04-fragmented-CH1"])
def test_cookie_validation_x25519mlkem768(adapters: Adapters, mtu: int) -> None:
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": str(mtu), "validate": "cookie"},
        client={"groups": MLKEM, "mtu": str(mtu), "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True)


def test_empty_key_share_triggers_hrr(adapters: Adapters) -> None:
    """S05: SSL_set1_client_key_shares with no groups sends an empty key_share."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM},
        client={"groups": MLKEM, "key_share": "empty"},
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)
    assert _client_hellos(srv, "<<") == ["empty", MLKEM], srv.stderr


def test_wrong_guess_triggers_hrr(adapters: Adapters) -> None:
    """S06 at PMTU 1280: client shares X25519, server only accepts the hybrid."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "1280"},
        client={"groups": f"X25519,{MLKEM}", "mtu": "1280", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)
    assert _client_hellos(srv, "<<") == ["X25519", MLKEM], srv.stderr
    # CH2 carries the 1216-byte share and is fragmented.
    assert _ch_records(srv) == 1 + 2, srv.stderr
    _assert_fits(cli, 1280)
    _assert_fits(srv, 1280)


def test_acceptable_share_wins_over_server_preference(adapters: Adapters) -> None:
    """Contract rule 1 (key share first): BoringSSL alone would send an HRR for X25519MLKEM768
    (tls1_get_shared_group in ssl/extensions.cc), so the adapter reorders its groups."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"{MLKEM},X25519", "key_share": "X25519"},
    )
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv, "X25519", hrr=False)
    assert "key share first: selecting X25519" in srv.stderr, srv.stderr


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
    assert srv.result["error"] == "handshake: NO_SHARED_GROUP", srv.result
    assert cli.result["error"] == "handshake: HANDSHAKE_FAILURE_ON_CLIENT_HELLO", cli.result


def test_default_key_share_sends_two_shares(adapters: Adapters) -> None:
    """--key-share=default: BoringSSL shares up to two groups, at most one post-quantum."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"{MLKEM},X25519,secp256r1", "key_share": "default"},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert _client_hellos(srv, "<<") == [f"{MLKEM},X25519"], srv.stderr


def test_default_mtu_is_library_default(adapters: Adapters) -> None:
    """--mtu=default: the adapter's BIO answers no MTU query, so BoringSSL uses 1472-byte
    datagrams, 20 bytes more than a 1500-byte IPv6 path allows."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "default"},
        client={"groups": MLKEM, "mtu": "default", "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert _ch_records(srv) == 1, srv.stderr
    assert max(_datagrams(srv)) == BSSL_DEFAULT_DATAGRAM, srv.stderr


def _assert_no_handshake(run: Run, code: int, error: str) -> None:
    expected = {"event": "result", "ok": False, "version": None, "group": None, "hrr": None}
    expected |= {"hrr_cookie": None, "hrr_group": None, "error": run.result["error"]}
    assert (run.code, run.result) == (code, expected), run.stderr
    assert error in run.result["error"], run.result


def test_cookie_validation_reported_unsupported(adapters: Adapters) -> None:
    proc = subprocess.run(
        adapters.args("server", validate="cookie"), capture_output=True, text=True, timeout=TIMEOUT
    )
    assert '"ready"' not in proc.stdout
    run = Run(proc.returncode, _result(proc.stdout), proc.stderr)
    _assert_no_handshake(run, 2, "--validate=cookie not possible")


@pytest.mark.parametrize("role", ["client", "server"])
@pytest.mark.parametrize("group", ["MLKEM512X25519", "SecP256r1MLKEM768", "X448"])
def test_unimplemented_group_is_unsupported(adapters: Adapters, role: str, group: str) -> None:
    """ssl/ssl_key_share.cc kNamedGroups has neither group."""
    run = adapters.run(adapters.args(role, 1, groups=f"{group},X25519"))
    _assert_no_handshake(run, 2, f"group {group} not implemented")


@pytest.mark.parametrize("role", ["client", "server"])
@pytest.mark.parametrize("mtu", [200, 275])
def test_mtu_below_library_minimum_is_unsupported(adapters: Adapters, role: str, mtu: int) -> None:
    """SSL_set_mtu rejects payloads under 228 bytes (kMinMTU), i.e. --mtu below 276."""
    run = adapters.run(adapters.args(role, 1, mtu=str(mtu)))
    _assert_no_handshake(run, 2, f"--mtu={mtu} rejected")


def test_smallest_mtu_works(adapters: Adapters) -> None:
    """--mtu=276 is the smallest the library accepts; every datagram stays within 228 bytes."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "276"},
        client={"groups": MLKEM, "mtu": "276", "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    _assert_fits(cli, 276)
    _assert_fits(srv, 276)


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
        "empty-group": {"groups": "X25519,,secp256r1"},
        "duplicate-group": {"groups": "X25519,x25519"},
    },
    "server": {
        "missing-validate": {"validate": None},
        "missing-mtu": {"mtu": None},
        "missing-key": {"key": None},
        "client-option": {"key_share": "default"},
        "bad-validate": {"validate": "maybe"},
        "bad-port": {"port": "70000"},
        "bad-mtu": {"mtu": "48"},
        "bad-variant": {"variant": "accept"},
        "tls-transport": {"transport": "tls"},
    },
}


@pytest.mark.parametrize(
    "role,opts",
    [(role, opts) for role, cases in USAGE_ERRORS.items() for opts in cases.values()],
    ids=[f"{role}-{name}" for role, cases in USAGE_ERRORS.items() for name in cases],
)
def test_usage_errors_exit_64(adapters: Adapters, role: str, opts: dict) -> None:
    args = adapters.args(role, 4433 if role == "client" else 0, **opts)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    assert '"ready"' not in proc.stdout
    _assert_no_handshake(Run(proc.returncode, _result(proc.stdout), proc.stderr), 64, "usage:")


def test_duplicate_option_is_usage_error(adapters: Adapters) -> None:
    args = [*adapters.args("client", 4433), "--mtu=1280"]
    _assert_no_handshake(adapters.run(args), 64, "given twice")


def test_client_rejects_untrusted_server(adapters: Adapters, tmp_path: Path) -> None:
    other = pki.generate(tmp_path / "other-pki")
    srv = adapters.start_server(cert=str(other.server_cert), key=str(other.server_key))
    cli = adapters.run_client(srv)
    assert cli.code == 1, cli.stderr
    assert cli.result["ok"] is False
    assert cli.result["error"] == "handshake: CERTIFICATE_VERIFY_FAILED", cli.result
    assert srv.finish().code == 1


# --- Against other implementations -------------------------------------------------------------
# These need the peer's build too and skip without it; docs/background.md lists the claims.


@pytest.fixture
def peer(
    require_impl, test_pki: pki.TestPki, tmp_path: Path
) -> Iterator[Callable[[str], Adapters]]:
    made: list[Adapters] = []

    def get(name: str) -> Adapters:
        (tmp_path / name).mkdir(exist_ok=True)
        made.append(Adapters(require_impl(name).adapter, test_pki, tmp_path / name))
        return made[-1]

    yield get
    for a in made:
        a.kill_all()


def _cross(client: Adapters, server: Adapters, srv: dict, cli: dict) -> tuple[Run, Run]:
    s = server.start_server(**srv)
    try:
        c = client.run(client.args("client", s.port, **cli), timeout=HANG_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f"client did not finish within {HANG_TIMEOUT}s") from e
    return c, s.finish()


DEFAULTS = {"groups": BSSL_DEFAULT_GROUPS, "mtu": "default"}


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="wolfSSL 5.9.4 with its default HRR cookie accepts a fragmented ClientHello only if "
    "the first fragment holds the whole cookie extension (src/dtls.c DoClientHelloStateless). "
    "BoringSSL writes the cookie after key_share (ssl/extensions.cc kExtensions), so its "
    "1468-byte CH2 splits at its 1472-byte default datagram with the cookie's last 21 bytes "
    "in fragment 2, which wolfSSL drops on every retransmission",
)
def test_defaults_against_wolfssl_cookie_server(adapters: Adapters, peer) -> None:
    """docs/background.md: BoringSSL and wolfSSL do not interoperate in default configurations."""
    cli, srv = _cross(adapters, peer("wolfssl"), {**DEFAULTS, "validate": "cookie"}, {**DEFAULTS})
    _assert_ok(cli, MLKEM, hrr=True, cookie=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True)


def test_defaults_against_wolfssl_server_without_cookie(adapters: Adapters, peer) -> None:
    """Control: without the cookie the default 1379-byte CH1 fits one datagram and is accepted."""
    cli, srv = _cross(adapters, peer("wolfssl"), {**DEFAULTS, "validate": "off"}, {**DEFAULTS})
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert _client_hellos(cli, ">>") == [f"{MLKEM},X25519"], cli.stderr


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="wolfSSL 5.9.4 wolfSSL_accept() drops a fragmented CH1 even with the cookie off "
    "(src/dtls13.c, src/dtls.c DoClientHelloStateless); see implementations/wolfssl/README.md",
)
def test_fragmented_pq_ch1_against_wolfssl_server(adapters: Adapters, peer) -> None:
    """S03 against wolfSSL: background.md says BoringSSL clients with a PQ share cannot connect."""
    opts = {"groups": MLKEM, "mtu": "1280"}
    cli, _ = _cross(
        adapters, peer("wolfssl"), {**opts, "validate": "off"}, {**opts, "key_share": MLKEM}
    )
    _assert_ok(cli, MLKEM, hrr=False)


def test_fragmented_pq_ch1_against_wolfssl_accept_tls13(adapters: Adapters, peer) -> None:
    opts = {"groups": MLKEM, "mtu": "1280"}
    srv_opts = {**opts, "validate": "off", "variant": "accept-tls13"}
    cli, srv = _cross(adapters, peer("wolfssl"), srv_opts, {**opts, "key_share": MLKEM})
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    _assert_fits(cli, 1280)


@pytest.mark.parametrize("server", ["openssl", "wolfssl"])
def test_empty_key_share_against_other_servers(adapters: Adapters, peer, server: str) -> None:
    """S05, BoringSSL client: background.md says BoringSSL does not handle an empty key_share."""
    opts = {"groups": MLKEM, "mtu": "1500"}
    cli, srv = _cross(
        adapters, peer(server), {**opts, "validate": "off"}, {**opts, "key_share": "empty"}
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)
    assert _client_hellos(cli, ">>") == ["empty", MLKEM], cli.stderr


def test_wolfssl_empty_key_share_against_boringssl_server(adapters: Adapters, peer) -> None:
    """S05 with a BoringSSL server; the OpenSSL client cannot send an empty key_share."""
    opts = {"groups": MLKEM, "mtu": "1500"}
    cli, srv = _cross(
        peer("wolfssl"), adapters, {**opts, "validate": "off"}, {**opts, "key_share": "empty"}
    )
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, hrr_group=True)
    assert _client_hellos(srv, "<<") == ["empty", MLKEM], srv.stderr
