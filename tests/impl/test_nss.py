"""NSS adapter self-interop on loopback, without the proxy (real builds, real UDP sockets)."""

from __future__ import annotations

import datetime
import json
import re
import select
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dtls_interop import pki

TIMEOUT = 20.0
HOST = "127.0.0.1"
IP_UDP_OVERHEAD = 48  # --mtu is the IP path MTU; the contract reserves IPv6 + UDP headers
MLKEM = "X25519MLKEM768"
# Largest datagram NSS 3.134 sends: 1472 (first dtlscon.c COMMON_MTU_VALUES entry) - 55.
NSS_MAX_DATAGRAM = 1417
MIN_MTU = NSS_MAX_DATAGRAM + IP_UDP_OVERHEAD


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


@pytest.fixture
def adapters(require_impl, test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Adapters]:
    a = Adapters(require_impl("nss").adapter, test_pki, tmp_path)
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


def _assert_no_handshake(run: Run, code: int, error: str) -> None:
    expected = {"event": "result", "ok": False, "version": None, "group": None, "hrr": None}
    expected |= {"hrr_cookie": None, "hrr_group": None, "error": run.result["error"]}
    assert (run.code, run.result) == (code, expected), run.stderr
    assert error in run.result["error"], run.result


def _big_server_pki(directory: Path) -> pki.TestPki:
    """A CA and a leaf grown to about 3 kB by extra SANs, so the server flight hits NSS's cap."""
    test_pki = pki.generate(directory)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dtls-interop big CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    names = [x509.DNSName("localhost")]
    names += [x509.DNSName(f"padding-{i:03d}.example") for i in range(120)]
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    test_pki.ca_cert.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    test_pki.server_cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    test_pki.server_key.write_bytes(key)
    return test_pki


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


def test_runs_pinned_libraries(adapters: Adapters, repo_root: Path) -> None:
    """The adapter loads the pinned build, not a system NSS (build.sh links with DT_RPATH)."""
    run = adapters.run(adapters.args("client", 1, mtu="200"))
    assert run.stderr.startswith("NSS 3.134, NSPR 4.41,"), run.stderr
    built = (repo_root / ".build" / "nss" / ".built").read_text().splitlines()
    assert built[0] == "nss 3.134", built


def test_x25519mlkem768_self_interop(adapters: Adapters) -> None:
    """S02: the NSS CH1 with a hybrid share is a 1374-byte record, below NSS's fragment cap."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM},
        client={"groups": MLKEM, "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert cli.stderr.count(">> ClientHello") == 1, cli.stderr
    assert _ch_records(srv) == 1, srv.stderr
    _assert_fits(cli, 1500)
    _assert_fits(srv, 1500)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="NSS 3.134 has no public DTLS MTU setting: its estimate starts at 1472 "
    "(lib/ssl/dtlscon.c COMMON_MTU_VALUES) and only drops after retransmissions, so the "
    "adapter cannot guarantee --mtu=1280 and exits 2",
)
def test_x25519mlkem768_fragmented_ch1(adapters: Adapters) -> None:
    """S03 with an NSS client; the client is checked first so the xfail does not wait."""
    srv = adapters.start_server(groups=MLKEM, mtu="default")
    cli = adapters.run_client(srv, groups=MLKEM, mtu="1280", key_share=MLKEM)
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv.finish(), MLKEM, hrr=False)


def test_cookie_validation_x25519mlkem768(adapters: Adapters) -> None:
    """A validation-only HRR carries a cookie but no selected_group."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "validate": "cookie"},
        client={"groups": MLKEM, "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True)
    assert cli.stderr.count(">> ClientHello") == 2, cli.stderr
    # The cookie grows CH2 past the 1383-byte fragment cap, so CH2 is two records.
    assert _ch_records(srv) == 1 + 2, srv.stderr
    _assert_fits(cli, 1500)
    _assert_fits(srv, 1500)


def test_cookie_and_wrong_guess_share_one_hrr(adapters: Adapters) -> None:
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "validate": "cookie"},
        client={"groups": f"X25519,{MLKEM}", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True, hrr_group=True)
    assert cli.stderr.count(">> ClientHello") == 2, cli.stderr


def test_wrong_guess_triggers_hrr(adapters: Adapters) -> None:
    """S06. NSS servers put a cookie into every HRR, so hrr_cookie is true even with
    --validate=off (tls13_SendHelloRetryRequest always calls tls13_MakeHrrCookie)."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM},
        client={"groups": f"X25519,{MLKEM}", "key_share": "X25519"},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True, hrr_group=True)


def test_acceptable_share_wins_over_server_preference(adapters: Adapters) -> None:
    """Contract rule 1 (key share first): no HRR just to get the server's preferred group."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"X25519,{MLKEM}", "key_share": "X25519"},
    )
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv, "X25519", hrr=False)


def test_key_share_first_beyond_next_slot(adapters: Adapters) -> None:
    """Unaided, NSS only takes a share for the slot after its preferred group (and only of
    similar strength, tls13_isGroupAcceptable); here it would send an HRR for secp384r1."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"secp384r1,{MLKEM},X25519"},
        client={"groups": f"X25519,{MLKEM},secp384r1", "key_share": "X25519"},
    )
    _assert_ok(cli, "X25519", hrr=False)
    _assert_ok(srv, "X25519", hrr=False)
    assert "NSS group order: X25519,secp384r1,X25519MLKEM768" in srv.stderr, srv.stderr


def test_hrr_selects_highest_ranked_server_group(adapters: Adapters) -> None:
    """Contract rule 2: without a usable share, the HRR follows the server's order."""
    cli, srv = _handshake(
        adapters,
        server={"groups": f"{MLKEM},X25519"},
        client={"groups": f"secp256r1,X25519,{MLKEM}", "key_share": "secp256r1"},
    )
    _assert_ok(cli, MLKEM, hrr=True, cookie=True, hrr_group=True)
    _assert_ok(srv, MLKEM, hrr=True, cookie=True, hrr_group=True)


def test_no_mutual_group_fails(adapters: Adapters) -> None:
    """Contract rule 3."""
    cli, srv = _handshake(
        adapters, server={"groups": MLKEM}, client={"groups": "X25519", "key_share": "X25519"}
    )
    assert (cli.code, cli.result["ok"]) == (1, False), cli.stderr
    assert (srv.code, srv.result["ok"]) == (1, False), srv.stderr
    assert "SSL_ERROR_NO_CYPHER_OVERLAP" in srv.result["error"]


def test_default_mtu_stays_within_nss_cap(adapters: Adapters) -> None:
    """--mtu=default configures nothing; NSS's own estimate caps every datagram."""
    cli, srv = _handshake(
        adapters,
        server={"groups": MLKEM, "mtu": "default"},
        client={"groups": MLKEM, "mtu": "default", "key_share": MLKEM},
    )
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert max(_datagrams(cli) + _datagrams(srv)) <= NSS_MAX_DATAGRAM


def test_smallest_supported_mtu_holds_large_flight(require_impl, tmp_path: Path) -> None:
    """With a 3 kB leaf the server flight is cut into datagrams of exactly NSS's cap."""
    a = Adapters(require_impl("nss").adapter, _big_server_pki(tmp_path / "big"), tmp_path)
    try:
        cli, srv = _handshake(
            a,
            server={"groups": MLKEM, "mtu": str(MIN_MTU)},
            client={"groups": MLKEM, "mtu": str(MIN_MTU), "key_share": MLKEM},
        )
    finally:
        a.kill_all()
    _assert_ok(cli, MLKEM, hrr=False)
    _assert_ok(srv, MLKEM, hrr=False)
    assert max(_datagrams(srv)) == NSS_MAX_DATAGRAM, srv.stderr
    assert len(_datagrams(srv)) >= 4, srv.stderr


@pytest.mark.parametrize("role", ["client", "server"])
@pytest.mark.parametrize("mtu", [1280, MIN_MTU - 1])
def test_mtu_below_nss_cap_is_unsupported(adapters: Adapters, role: str, mtu: int) -> None:
    run = adapters.run(adapters.args(role, 1, mtu=str(mtu)))
    _assert_no_handshake(run, 2, "NSS has no DTLS MTU setting")


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="NSS 3.134 clients always send a key share: tls13_SetupClientHello creates one for "
    "the first enabled group and fails with SSL_ERROR_NO_CIPHERS_SUPPORTED without one",
)
def test_empty_key_share_triggers_hrr(adapters: Adapters) -> None:
    """S05 with an NSS client; the client is checked first so the xfail does not wait."""
    srv = adapters.start_server(groups=MLKEM)
    cli = adapters.run_client(srv, groups=MLKEM, key_share="empty")
    _assert_ok(cli, MLKEM, hrr=True, hrr_group=True)
    _assert_ok(srv.finish(), MLKEM, hrr=True, hrr_group=True)


def test_empty_key_share_reported_unsupported(adapters: Adapters) -> None:
    cli = adapters.run(adapters.args("client", 1, groups=MLKEM, key_share="empty"))
    _assert_no_handshake(cli, 2, "empty key_share")


def test_share_for_later_group_reported_unsupported(adapters: Adapters) -> None:
    """NSS shares for the first entries of its group list, which also orders supported_groups."""
    cli = adapters.run(adapters.args("client", 1, groups=f"{MLKEM},X25519", key_share="X25519"))
    _assert_no_handshake(cli, 2, "first --groups entry")


@pytest.mark.parametrize("role", ["client", "server"])
@pytest.mark.parametrize("group", ["MLKEM512X25519", "MLKEM768"])
def test_unimplemented_group_is_unsupported(adapters: Adapters, role: str, group: str) -> None:
    """NSS 3.134 has neither (lib/ssl/sslt.h SSLNamedGroup)."""
    run = adapters.run(adapters.args(role, 1, groups=f"{group},X25519"))
    _assert_no_handshake(run, 2, group)


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
        "bad-variant": {"variant": "accept"},
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
    args = [*adapters.args("client", 4433), "--mtu=1500"]
    _assert_no_handshake(adapters.run(args), 64, "given twice")


def test_client_rejects_untrusted_server(adapters: Adapters, tmp_path: Path) -> None:
    other = pki.generate(tmp_path / "other-pki")
    srv = adapters.start_server(cert=str(other.server_cert), key=str(other.server_key))
    cli = adapters.run_client(srv)
    assert cli.code == 1, cli.stderr
    assert cli.result["ok"] is False
    assert "certificate verify failed: SEC_ERROR_UNKNOWN_ISSUER" in cli.result["error"]
    assert srv.finish().code == 1
