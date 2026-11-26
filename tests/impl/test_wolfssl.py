"""wolfSSL adapter self-interop over real loopback UDP and TCP (no harness proxy yet)."""

from __future__ import annotations

import json
import queue
import re
import selectors
import signal
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass

import pytest

from dtls_interop import pki
from dtls_interop.implementations import Implementation

HOST = "127.0.0.1"
READY_TIMEOUT = 10.0
RUN_TIMEOUT = 20.0
# Scenarios expected to hang (silently dropped datagrams) only need a few retransmissions.
HANG_TIMEOUT = 8.0
EXIT_UNSUPPORTED = 2
EXIT_USAGE = 64
# Contract order of the result line fields.
RESULT_FIELDS = [
    "event",
    "ok",
    "version",
    "group",
    "hrr",
    "hrr_cookie",
    "hrr_group",
    "resumed",
    "error",
]


@dataclass
class Outcome:
    rc: int | None  # None: killed after timeout
    result: dict | None
    stderr: str


@dataclass
class PairOutcome:
    server: Outcome
    client: Outcome


def _result_line(stdout: str) -> dict | None:
    results = [
        json.loads(line)
        for line in stdout.splitlines()
        if line.strip() and json.loads(line).get("event") == "result"
    ]
    return results[-1] if results else None


def _finish(proc: subprocess.Popen[str], timeout: float) -> Outcome:
    try:
        out, err = proc.communicate(timeout=timeout)
        rc: int | None = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        rc = None
    return Outcome(rc=rc, result=_result_line(out), stderr=err)


def _wait_ready(proc: subprocess.Popen[str]) -> int:
    """Wait for the server's ready line and return the port it bound."""
    assert proc.stdout is not None
    lines: queue.Queue[str] = queue.Queue()
    threading.Thread(target=lambda: lines.put(proc.stdout.readline()), daemon=True).start()
    try:
        line = lines.get(timeout=READY_TIMEOUT)
    except queue.Empty:
        proc.kill()
        pytest.fail(f"server not ready after {READY_TIMEOUT}s: {proc.communicate()[1]}")
    ready = json.loads(line or "{}")
    if ready.get("event") != "ready" or not 0 < ready.get("port", 0) < 65536:
        pytest.fail(f"expected ready line with port, got {line!r}; stderr: {proc.communicate()[1]}")
    return ready["port"]


@pytest.fixture
def wolfssl(require_impl: Callable[[str], Implementation]) -> Implementation:
    return require_impl("wolfssl")


def _base(
    wolfssl: Implementation,
    test_pki: pki.TestPki,
    role: str,
    variant: str,
    transport: str = "dtls",
    resume: str = "off",
) -> list[str]:
    """Role-specific required options in the runner's --opt=value form."""
    cmd = [str(wolfssl.adapter), f"--role={role}", f"--variant={variant}", f"--host={HOST}"]
    cmd += [f"--transport={transport}", f"--resume={resume}", f"--ca={test_pki.ca_cert}"]
    if role == "server":
        cmd += [f"--cert={test_pki.server_cert}", f"--key={test_pki.server_key}"]
    return cmd


@pytest.fixture
def run_pair(wolfssl: Implementation, test_pki: pki.TestPki) -> Callable[..., PairOutcome]:
    def run(
        server_args: list[str],
        client_args: list[str],
        *,
        via: Callable[[int], AbstractContextManager[int]] | None = None,
        timeout: float = RUN_TIMEOUT,
        variant: str = "default",
        transport: str = "dtls",
        resume: str = "off",
    ) -> PairOutcome:
        # The only wolfSSL variant is server-only, so the client always runs "default".
        server_cmd = _base(wolfssl, test_pki, "server", variant, transport, resume)
        server = subprocess.Popen(
            [*server_cmd, "--port=0", *server_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            port = _wait_ready(server)
            with (via or _direct)(port) as client_port:
                client_cmd = _base(wolfssl, test_pki, "client", "default", transport, resume)
                client = subprocess.Popen(
                    [*client_cmd, f"--port={client_port}", *client_args],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                client_outcome = _finish(client, timeout)
            server_outcome = _finish(server, 5.0 if client_outcome.rc is not None else 0.1)
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()
        return PairOutcome(server=server_outcome, client=client_outcome)

    return run


@contextmanager
def _direct(port: int) -> Iterator[int]:
    yield port


def _tx_sizes(stderr: str) -> list[int]:
    return [int(n) for n in re.findall(r"\] tx (\d+)B", stderr)]


def _assert_ok(
    o: PairOutcome,
    group: str,
    hrr: bool,
    *,
    cookie: bool = False,
    hrr_group: bool = False,
    max_datagram: int | None = None,
    version: str = "DTLSv1.3",
    resumed: bool = False,
) -> None:
    for role, side in (("client", o.client), ("server", o.server)):
        assert side.rc == 0, f"{role} rc={side.rc} result={side.result}\n{side.stderr}"
        assert side.result == {
            "event": "result",
            "ok": True,
            "version": version,
            "group": group,
            "hrr": hrr,
            "hrr_cookie": hrr and cookie,
            "hrr_group": hrr and hrr_group,
            "resumed": resumed,
            "error": None,
        }, f"{role}: {side.stderr}"
        assert list(side.result) == RESULT_FIELDS
        if max_datagram is not None:
            sizes = _tx_sizes(side.stderr)
            assert sizes and max(sizes) <= max_datagram, f"{role} sent {sizes}"


def _args(groups: str, mtu: int | str, validate: str, key_share: str | None = None) -> tuple:
    server = [f"--groups={groups}", f"--mtu={mtu}", f"--validate={validate}"]
    client = [f"--groups={groups}", f"--mtu={mtu}", f"--key-share={key_share or groups}"]
    return server, client


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_x25519_self_interop(run_pair, validate: str) -> None:
    o = run_pair(*_args("X25519", 1500, validate))
    # The cookie-only HRR carries no key_share: the share was acceptable.
    _assert_ok(o, "X25519", hrr=validate == "cookie", cookie=True, hrr_group=False)


@pytest.mark.parametrize("mtu", [1500, 1280])
@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_x25519mlkem768_self_interop(run_pair, mtu: int, validate: str) -> None:
    o = run_pair(*_args("X25519MLKEM768", mtu, validate, key_share="default"))
    # At MTU 1280 CH1 with the share does not fit, so the client sends an empty key_share instead.
    hrr = validate == "cookie" or mtu == 1280
    _assert_ok(
        o,
        "X25519MLKEM768",
        hrr=hrr,
        cookie=validate == "cookie",
        hrr_group=mtu == 1280,
        max_datagram=mtu - 48,  # --mtu is the IP path MTU; IPv6 + UDP headers take 48 bytes
    )


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_secp256r1mlkem768_self_interop(run_pair, validate: str) -> None:
    o = run_pair(*_args("SecP256r1MLKEM768", 1500, validate, key_share="default"))
    # The 1443-byte CH1 (psk_key_exchange_modes added by session tickets) would fit in 1452, but
    # wolfSSL compares the whole record with the plaintext limit 1439 and empties the key share.
    _assert_ok(
        o,
        "SecP256r1MLKEM768",
        hrr=True,
        cookie=validate == "cookie",
        hrr_group=True,
        max_datagram=1452,
    )
    first_ch = re.search(r"tx \d+B \| rec=22 epoch=0 hs=1 .*", o.client.stderr)
    assert first_ch is not None and "51:2()," in first_ch[0], o.client.stderr


def test_requested_secp256r1mlkem768_share_at_1500_is_unsupported(run_pair) -> None:
    # The same 13-byte-strict size check, so an explicit share is refused even at MTU 1500.
    o = run_pair(*_args("SecP256r1MLKEM768", 1500, "off"), timeout=HANG_TIMEOUT)
    assert o.client.rc == EXIT_UNSUPPORTED, o.client.stderr
    assert o.client.result is not None and "empty key_share" in o.client.result["error"]


@pytest.mark.parametrize("mtu", [1280, "default"])
def test_requested_share_that_does_not_fit_ch1_is_unsupported(run_pair, mtu) -> None:
    """wolfSSL (WOLFSSL_DTLS_CH_FRAG) would replace the share with an empty key_share instead of
    fragmenting CH1 (src/tls13.c), so the adapter exits 2 before sending anything."""
    o = run_pair(*_args("X25519MLKEM768", mtu, "off"), timeout=HANG_TIMEOUT)
    assert o.client.rc == EXIT_UNSUPPORTED, o.client.stderr
    assert o.client.result is not None and "empty key_share" in o.client.result["error"]
    assert " tx " not in o.client.stderr, o.client.stderr
    assert o.server.rc is None, "the server must not have received a ClientHello"


def test_default_mtu_is_1400_and_too_small_for_x25519mlkem768_ch1(run_pair) -> None:
    o = run_pair(*_args("X25519MLKEM768", "default", "off", key_share="default"))
    # WOLFSSL_MAX_MTU is 1400 and the X25519MLKEM768 CH1 is 1410 bytes, so the share is dropped.
    _assert_ok(o, "X25519MLKEM768", hrr=True, hrr_group=True, max_datagram=1400)
    assert max(_tx_sizes(o.client.stderr)) == 1400, o.client.stderr


def test_default_key_share_is_first_group(run_pair) -> None:
    server = ["--groups=X25519MLKEM768,X25519", "--mtu=1500", "--validate=off"]
    client = ["--groups=X25519,X25519MLKEM768", "--mtu=1500", "--key-share=default"]
    o = run_pair(server, client)
    _assert_ok(o, "X25519", hrr=False)
    assert "51:38(0x001d)" in o.client.stderr, o.client.stderr


def test_server_selects_key_share_first(run_pair) -> None:
    # Contract rule 1: an acceptable share wins over a group the server ranks higher.
    server = ["--groups=X25519MLKEM768,X25519", "--mtu=1500", "--validate=off"]
    client = ["--groups=X25519MLKEM768,X25519", "--mtu=1500", "--key-share=X25519"]
    _assert_ok(run_pair(server, client), "X25519", hrr=False)


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_empty_key_share_triggers_hrr(run_pair, validate: str) -> None:
    # Contract rule 2: the HRR selects the server's highest-ranked group the client supports.
    server = ["--groups=X25519MLKEM768,X25519", "--mtu=1500", f"--validate={validate}"]
    client = ["--groups=X25519,X25519MLKEM768", "--mtu=1500", "--key-share=empty"]
    o = run_pair(server, client)
    _assert_ok(o, "X25519MLKEM768", hrr=True, cookie=validate == "cookie", hrr_group=True)


def test_wrong_guess_triggers_hrr(run_pair) -> None:
    server = ["--groups=X25519MLKEM768", "--mtu=1500", "--validate=off"]
    client = ["--groups=X25519,X25519MLKEM768", "--mtu=1500", "--key-share=X25519"]
    _assert_ok(run_pair(server, client), "X25519MLKEM768", hrr=True, hrr_group=True)


def test_no_mutual_group_fails(run_pair) -> None:
    server = ["--groups=X25519MLKEM768", "--mtu=1500", "--validate=off"]
    client = ["--groups=X25519", "--mtu=1500", "--key-share=X25519"]
    o = run_pair(server, client)
    for role, side in (("client", o.client), ("server", o.server)):
        assert side.rc == 1, f"{role} rc={side.rc}\n{side.stderr}"
        assert side.result is not None and side.result["ok"] is False


def test_teardown_exchanges_close_notify(run_pair) -> None:
    o = run_pair(*_args("X25519", 1500, "off"))
    _assert_ok(o, "X25519", hrr=False)
    assert "received the server's close_notify" in o.client.stderr, o.client.stderr
    assert "received the client's close_notify" in o.server.stderr, o.server.stderr


def _variants(wolfssl: Implementation) -> dict[str, set[str]]:
    """Variant name -> roles, from 'ROLE NAME: description' lines."""
    variants = {}
    for line in (wolfssl.adapter.parent / "variants").read_text().splitlines():
        role, name = line.split(":", 1)[0].split()
        variants[name] = {"client", "server"} if role == "both" else {role}
    return variants


def _run_once(cmd: list[str]) -> tuple[int, dict | None]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    return proc.returncode, _result_line(proc.stdout)


@pytest.mark.parametrize("role", ["client", "server"])
def test_variants_are_accepted_only_in_their_roles(
    wolfssl: Implementation, test_pki: pki.TestPki, role: str
) -> None:
    variants = _variants(wolfssl)
    assert variants == {"accept-tls13": {"server"}}
    for variant, roles in {"default": {"client", "server"}, **variants}.items():
        # An unsupported group stops the adapter right after option parsing.
        cmd = [*_base(wolfssl, test_pki, role, variant), "--port=9", "--mtu=1500"]
        cmd += ["--groups=MLKEM512X25519"]
        cmd += ["--key-share=default"] if role == "client" else ["--validate=off"]
        rc, _ = _run_once(cmd)
        expected = EXIT_UNSUPPORTED if role in roles else EXIT_USAGE
        assert rc == expected, f"{variant}: rc={rc}"


_TRANSPORT_RESUME = ["--transport", "dtls", "--resume", "off"]
_VALID = {
    "client": ["--groups", "X25519", "--mtu", "1500", "--key-share", "X25519", *_TRANSPORT_RESUME],
    "server": ["--groups", "X25519", "--mtu", "1500", "--validate", "off", *_TRANSPORT_RESUME],
}


def _space_form_cmd(wolfssl: Implementation, test_pki: pki.TestPki, role: str) -> list[str]:
    """All required options of a role in the '--opt value' form, minus the role-specific rest."""
    cmd = [str(wolfssl.adapter), "--role", role, "--variant", "default", "--host", HOST]
    cmd += ["--port", "9", "--ca", str(test_pki.ca_cert)]
    if role == "server":
        cmd += ["--cert", str(test_pki.server_cert), "--key", str(test_pki.server_key)]
    return cmd


def _without(args: list[str], option: str) -> list[str]:
    i = args.index(option)
    return args[:i] + args[i + 2 :]


@pytest.mark.parametrize(
    ("role", "change"),
    [
        ("client", lambda a: _without(a, "--key-share")),
        ("server", lambda a: _without(a, "--validate")),
        ("client", lambda a: _without(a, "--mtu")),
        ("client", lambda a: [*a, "--no-such-option", "1"]),
        ("client", lambda a: [*a, "--psk-in", "/nonexistent"]),
        ("client", lambda a: [*a, "--validate", "off"]),
        ("server", lambda a: [*a, "--key-share", "X25519"]),
        ("client", lambda a: [*_without(a, "--mtu"), "--mtu", "abc"]),
        ("client", lambda a: [*_without(a, "--mtu"), "--mtu", "40"]),
        ("server", lambda a: [*_without(a, "--validate"), "--validate", "maybe"]),
        ("client", lambda a: [*_without(a, "--key-share"), "--key-share", "secp256r1"]),
        ("client", lambda a: [*_without(a, "--groups"), "--groups", "X25519,"]),
        ("client", lambda a: [*a, "--mtu", "1500"]),
        ("client", lambda a: _without(a, "--transport")),
        ("server", lambda a: _without(a, "--resume")),
        ("server", lambda a: [*_without(a, "--transport"), "--transport", "quic"]),
        ("client", lambda a: [*_without(a, "--resume"), "--resume", "psk"]),
        ("client", lambda a: [*_without(a, "--transport"), "--transport", "tls"]),
        ("server", lambda a: [*_without(a, "--transport"), "--transport", "tls"]),
        ("client", lambda a: [*a, "--resume", "off"]),
    ],
    ids=[
        "missing-key-share",
        "missing-validate",
        "missing-mtu",
        "unknown-option",
        "psk-option",
        "client-gets-validate",
        "server-gets-key-share",
        "mtu-not-a-number",
        "mtu-below-overhead",
        "bad-validate",
        "key-share-not-in-groups",
        "empty-group-entry",
        "duplicate-option",
        "missing-transport",
        "missing-resume",
        "bad-transport",
        "bad-resume",
        "client-tls-numeric-mtu",
        "server-tls-numeric-mtu",
        "duplicate-resume",
    ],
)
def test_usage_error_exits_64(
    wolfssl: Implementation, test_pki: pki.TestPki, role: str, change
) -> None:
    rc, result = _run_once(change(_space_form_cmd(wolfssl, test_pki, role) + _VALID[role]))
    assert rc == EXIT_USAGE
    assert result is not None and result["ok"] is False and result["error"].startswith("usage:")


@pytest.mark.parametrize(
    "extra", [["--port", "0"], ["--variant", "nope"], ["--variant", "accept-tls13"]]
)
def test_bad_client_port_or_variant_exits_64(
    wolfssl: Implementation, test_pki: pki.TestPki, extra: list[str]
) -> None:
    cmd = _space_form_cmd(wolfssl, test_pki, "client") + _VALID["client"]
    cmd = _without(cmd, extra[0]) + extra
    assert _run_once(cmd)[0] == EXIT_USAGE


@pytest.mark.parametrize("groups", ["MLKEM512X25519", "X25519,MLKEM768"])
@pytest.mark.parametrize("role", ["client", "server"])
def test_unsupported_group_exits_2(
    wolfssl: Implementation, test_pki: pki.TestPki, role: str, groups: str
) -> None:
    # Space-separated form: reaching the group check shows that form parses too.
    cmd = _without(_space_form_cmd(wolfssl, test_pki, role) + _VALID[role], "--groups")
    cmd += ["--groups", groups]
    if role == "client":
        cmd = [*_without(cmd, "--key-share"), "--key-share", "default"]
    rc, result = _run_once(cmd)
    assert rc == EXIT_UNSUPPORTED
    assert result is not None and result["ok"] is False and "unsupported" in result["error"]


# --- Fragmented CH1 towards the server --------------------------------------------------------
# The wolfSSL client never fragments CH1 (see the xfail above), so a relay splits its
# single-datagram CH1 into two records/datagrams, as a fragmenting client would send it.


def _split_ch1(datagram: bytes) -> list[bytes] | None:
    """Split a datagram holding exactly one complete plaintext CH1 record into two."""
    if len(datagram) < 25 or datagram[0] != 22 or datagram[3:5] != b"\x00\x00":
        return None
    rec_len = int.from_bytes(datagram[11:13])
    hs = datagram[13:]
    if len(hs) != rec_len or hs[0] != 1 or hs[4:6] != b"\x00\x00":
        return None
    msg_len = int.from_bytes(hs[1:4])
    if int.from_bytes(hs[6:9]) != 0 or int.from_bytes(hs[9:12]) != msg_len:
        return None
    body, cut = hs[12:], msg_len // 2
    seq = int.from_bytes(datagram[5:11])
    out = []
    for i, (off, frag) in enumerate(((0, body[:cut]), (cut, body[cut:]))):
        hdr = hs[:6] + off.to_bytes(3) + len(frag).to_bytes(3)
        record = datagram[:5] + (2 * seq + i).to_bytes(6) + (len(hdr) + len(frag)).to_bytes(2)
        out.append(record + hdr + frag)
    return out


def _renumber(datagram: bytes) -> bytes:
    """Keep client epoch-0 record numbers unique after splitting: seq n -> 2n."""
    if len(datagram) >= 13 and datagram[0] in (21, 22) and datagram[3:5] == b"\x00\x00":
        seq = int.from_bytes(datagram[5:11])
        return datagram[:5] + (2 * seq).to_bytes(6) + datagram[11:]
    return datagram


@contextmanager
def _ch1_splitting_relay(server_port: int) -> Iterator[int]:
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.bind((HOST, 0))
    back.connect((HOST, server_port))
    stop = threading.Event()
    client_addr: list[tuple[str, int]] = []

    def loop() -> None:
        sel = selectors.DefaultSelector()
        sel.register(front, selectors.EVENT_READ)
        sel.register(back, selectors.EVENT_READ)
        while not stop.is_set():
            for key, _ in sel.select(timeout=0.05):
                try:
                    data, addr = key.fileobj.recvfrom(65535)
                except ConnectionRefusedError:
                    continue
                if key.fileobj is front:
                    client_addr[:] = [addr]
                    for d in _split_ch1(data) or [_renumber(data)]:
                        back.send(d)
                elif client_addr:
                    front.sendto(data, client_addr[0])
        sel.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield front.getsockname()[1]
    finally:
        stop.set()
        thread.join()
        front.close()
        back.close()


@pytest.mark.xfail(
    strict=True,
    reason="wolfSSL 5.9.4 wolfSSL_accept() processes CH1 statelessly even after "
    "wolfSSL_disable_hrr_cookie() (only wolfSSL_accept_TLSv13() marks the peer stateful when "
    "the cookie is off), so a fragmented CH1 is dropped as 'Cookie probably missing from first "
    "fragment' (src/ssl_api_hs.c, src/dtls13.c); see the accept-tls13 variant",
)
def test_server_accepts_fragmented_ch1_without_validation(run_pair) -> None:
    server, client = _args("X25519MLKEM768", 1500, "off")
    o = run_pair(server, client, via=_ch1_splitting_relay, timeout=HANG_TIMEOUT)
    _assert_ok(o, "X25519MLKEM768", hrr=False)


def test_accept_tls13_variant_accepts_fragmented_ch1_without_validation(run_pair) -> None:
    server, client = _args("X25519MLKEM768", 1500, "off")
    o = run_pair(server, client, via=_ch1_splitting_relay, variant="accept-tls13")
    _assert_ok(o, "X25519MLKEM768", hrr=False)
    first = re.search(r"rx \d+B \| rec=22 epoch=0 hs=1 seq=0 frag=0\+(\d+)/(\d+)", o.server.stderr)
    assert first is not None and int(first[1]) < int(first[2]), o.server.stderr


@pytest.mark.xfail(
    strict=True,
    reason="wolfSSL 5.9.4 server with stateless HRR cookie silently drops a fragmented CH1 that "
    "has no cookie in its first fragment (src/dtls13.c, DoClientHelloStateless), in both "
    "variants; the client times out",
)
@pytest.mark.parametrize("variant", ["default", "accept-tls13"])
def test_server_accepts_fragmented_ch1_with_cookie(run_pair, variant: str) -> None:
    server, client = _args("X25519MLKEM768", 1500, "cookie")
    o = run_pair(server, client, via=_ch1_splitting_relay, timeout=HANG_TIMEOUT, variant=variant)
    _assert_ok(o, "X25519MLKEM768", hrr=True, cookie=True)


def test_relay_split_is_well_formed() -> None:
    body = bytes(range(256)) * 4
    hs = b"\x01" + len(body).to_bytes(3) + b"\x00\x00" + b"\x00" * 3 + len(body).to_bytes(3)
    record = b"\x16\xfe\xfd\x00\x00" + (3).to_bytes(6) + (len(hs) + len(body)).to_bytes(2)
    parts = _split_ch1(record + hs + body)
    assert parts is not None
    assert [int.from_bytes(p[5:11]) for p in parts] == [6, 7]
    assert b"".join(p[25:] for p in parts) == body


# --- TLS 1.3 over TCP -------------------------------------------------------------------------


def _tls_args(groups: str, validate: str, key_share: str | None = None) -> tuple:
    return _args(groups, "default", validate, key_share)


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_tls_x25519_self_interop(run_pair, validate: str) -> None:
    o = run_pair(*_tls_args("X25519", validate), transport="tls")
    _assert_ok(o, "X25519", hrr=validate == "cookie", cookie=True, version="TLSv1.3")
    assert "received the server's close_notify" in o.client.stderr, o.client.stderr
    assert "received the client's close_notify" in o.server.stderr, o.server.stderr


def test_tls_x25519mlkem768_sends_full_share_in_ch1(run_pair) -> None:
    # The DTLS CH1 size check does not apply to TLS: the 1.2 kB share goes into CH1.
    o = run_pair(*_tls_args("X25519MLKEM768", "off"), transport="tls")
    _assert_ok(o, "X25519MLKEM768", hrr=False, version="TLSv1.3")
    assert "51:1222(0x11ec)" in o.client.stderr, o.client.stderr


@contextmanager
def _tcp_trickle_relay(server_port: int) -> Iterator[int]:
    """Forward TCP in small delayed chunks, so records reach each peer split across reads."""
    listener = socket.create_server((HOST, 0))
    stop = threading.Event()

    def pump(src: socket.socket, dst: socket.socket) -> None:
        while not stop.is_set():
            try:
                data = src.recv(64)
            except OSError:
                break
            if not data:
                break
            for i in range(0, len(data), 7):
                dst.sendall(data[i : i + 7])
                time.sleep(0.0005)
        with suppress(OSError):
            dst.shutdown(socket.SHUT_WR)

    def serve() -> None:
        listener.settimeout(RUN_TIMEOUT)
        try:
            front, _ = listener.accept()
        except OSError:
            return
        back = socket.create_connection((HOST, server_port))
        for s in (front, back):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pumps = [threading.Thread(target=pump, args=p) for p in ((front, back), (back, front))]
        for p in pumps:
            p.start()
        for p in pumps:
            p.join()
        front.close()
        back.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


def test_tls_hrr_detected_across_split_records(run_pair) -> None:
    server = ["--groups=X25519MLKEM768,X25519", "--mtu=default", "--validate=cookie"]
    client = ["--groups=X25519,X25519MLKEM768", "--mtu=default", "--key-share=empty"]
    o = run_pair(server, client, via=_tcp_trickle_relay, transport="tls")
    _assert_ok(o, "X25519MLKEM768", hrr=True, cookie=True, hrr_group=True, version="TLSv1.3")
    assert re.search(r"rx record \d+B type=22 hs=2 len=\d+ exts=51:1124\(0x11ec\)", o.client.stderr)


def test_dtls_only_variant_with_tls_exits_2(wolfssl: Implementation, test_pki: pki.TestPki) -> None:
    cmd = [*_base(wolfssl, test_pki, "server", "accept-tls13", "tls"), "--port=0"]
    rc, result = _run_once([*cmd, "--groups=X25519", "--mtu=default", "--validate=off"])
    assert rc == EXIT_UNSUPPORTED
    assert result is not None and list(result) == RESULT_FIELDS
    assert result["ok"] is False and "DTLS-only" in result["error"]
    assert result["resumed"] is None and result["hrr"] is None and result["version"] is None


# --- Resumption with a session ticket -------------------------------------------------------


def _assert_both_connections(o: PairOutcome) -> None:
    for role, side in (("client", o.client), ("server", o.server)):
        for n in (1, 2):
            assert f"connection {n}: handshake done" in side.stderr, f"{role}: {side.stderr}"


def test_dtls_resumption_s10(run_pair) -> None:
    # S10 with the library's share choice: CH1 does not fit at MTU 1280, so both connections get
    # an HRR with cookie and group. S10's explicit share exits 2 like any CH1 that does not fit.
    o = run_pair(*_args("X25519MLKEM768", 1280, "cookie", key_share="default"), resume="ticket")
    _assert_ok(
        o,
        "X25519MLKEM768",
        hrr=True,
        cookie=True,
        hrr_group=True,
        resumed=True,
        max_datagram=1232,
    )
    _assert_both_connections(o)


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_dtls_x25519_resumption(run_pair, validate: str) -> None:
    o = run_pair(*_args("X25519", 1500, validate), resume="ticket")
    _assert_ok(o, "X25519", hrr=validate == "cookie", cookie=True, resumed=True)
    _assert_both_connections(o)


def test_dtls_resumption_pre_shared_key_makes_the_requested_share_unsupported(run_pair) -> None:
    # Connection 1 sends the 1410-byte CH1; with pre_shared_key the CH1 of connection 2 is too big.
    o = run_pair(*_args("X25519MLKEM768", 1500, "off"), resume="ticket", timeout=HANG_TIMEOUT)
    assert o.client.rc == EXIT_UNSUPPORTED, o.client.stderr
    assert o.client.result is not None
    assert o.client.result["error"].startswith("connection 2: unsupported: CH1 with the")
    assert "connection 1: handshake done" in o.client.stderr, o.client.stderr


def test_dtls_resumption_pre_shared_key_pushes_pq_ch1_past_mtu(run_pair) -> None:
    # The 1410-byte CH1 fits at MTU 1500; with the pre_shared_key extension it does not.
    o = run_pair(*_args("X25519MLKEM768", 1500, "off", key_share="default"), resume="ticket")
    _assert_ok(o, "X25519MLKEM768", hrr=True, hrr_group=True, resumed=True, max_datagram=1452)
    first_ch = re.findall(r"tx \d+B \| rec=22 epoch=0 hs=1 seq=0 .*", o.client.stderr)
    assert len(first_ch) == 2, o.client.stderr
    assert "51:1222(0x11ec)" in first_ch[0] and "51:2()," in first_ch[1], o.client.stderr
    assert "41:" in first_ch[1], o.client.stderr


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_tls_x25519_resumption(run_pair, validate: str) -> None:
    o = run_pair(*_tls_args("X25519", validate), transport="tls", resume="ticket")
    _assert_ok(o, "X25519", hrr=validate == "cookie", cookie=True, resumed=True, version="TLSv1.3")
    _assert_both_connections(o)


@contextmanager
def _ticketless_tls_server(test_pki: pki.TestPki) -> Iterator[int]:
    """A TLS 1.3 server (Python's OpenSSL) that issues no NewSessionTicket."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.num_tickets = 0
    ctx.load_cert_chain(test_pki.server_cert, test_pki.server_key)
    listener = socket.create_server((HOST, 0))
    listener.settimeout(RUN_TIMEOUT)
    errors: list[OSError] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                if tls.recv(4) == b"ping":
                    tls.sendall(b"pong")
                tls.unwrap()
        except OSError as e:
            errors.append(e)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        thread.join(timeout=5)


def test_client_without_ticket_fails_connection_1(
    wolfssl: Implementation, test_pki: pki.TestPki
) -> None:
    with _ticketless_tls_server(test_pki) as port:
        cmd = _base(wolfssl, test_pki, "client", "default", "tls", "ticket")
        cmd += [f"--port={port}", "--groups=X25519", "--mtu=default", "--key-share=X25519"]
        rc, result = _run_once(cmd)
    assert rc == 1
    assert result == {
        "event": "result",
        "ok": False,
        "version": "TLSv1.3",
        "group": "X25519",
        "hrr": False,
        "hrr_cookie": False,
        "hrr_group": False,
        "resumed": False,
        "error": "connection 1: no session ticket received",
    }


@pytest.mark.parametrize(("transport", "resume"), [("dtls", "off"), ("tls", "ticket")])
def test_deadline_result_line(
    wolfssl: Implementation, test_pki: pki.TestPki, transport: str, resume: str
) -> None:
    # SIGALRM is what the 60 s safety net delivers; its handler builds the JSON by hand.
    mtu = "1500" if transport == "dtls" else "default"
    cmd = [*_base(wolfssl, test_pki, "server", "default", transport, resume), "--port=0"]
    cmd += ["--groups=X25519", f"--mtu={mtu}", "--validate=off"]
    server = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _wait_ready(server)
    server.send_signal(signal.SIGALRM)
    outcome = _finish(server, 5.0)
    assert outcome.rc == 1, outcome.stderr
    assert outcome.result is not None and list(outcome.result) == RESULT_FIELDS
    assert outcome.result["ok"] is False and outcome.result["resumed"] is None
    prefix = "connection 1: " if resume == "ticket" else ""
    assert outcome.result["error"] == f"{prefix}timeout"
