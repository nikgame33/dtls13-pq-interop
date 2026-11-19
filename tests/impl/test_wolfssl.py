"""wolfSSL adapter self-interop over real loopback UDP (no harness proxy yet)."""

from __future__ import annotations

import json
import os
import queue
import re
import selectors
import socket
import subprocess
import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

import pytest

from dtls_interop import pki
from dtls_interop.implementations import Implementation

HOST = "127.0.0.1"
READY_TIMEOUT = 10.0
RUN_TIMEOUT = 20.0
# Scenarios expected to hang (silently dropped datagrams) only need a few retransmissions.
HANG_TIMEOUT = 8.0


@dataclass
class Outcome:
    rc: int | None  # None: killed after timeout
    result: dict | None
    stderr: str


@dataclass
class PairOutcome:
    server: Outcome
    client: Outcome


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


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


def _wait_ready(proc: subprocess.Popen[str]) -> None:
    assert proc.stdout is not None
    lines: queue.Queue[str] = queue.Queue()
    threading.Thread(target=lambda: lines.put(proc.stdout.readline()), daemon=True).start()
    try:
        line = lines.get(timeout=READY_TIMEOUT)
    except queue.Empty:
        proc.kill()
        pytest.fail(f"server not ready after {READY_TIMEOUT}s: {proc.communicate()[1]}")
    if json.loads(line or "{}").get("event") != "ready":
        pytest.fail(f"expected ready line, got {line!r}; stderr: {proc.communicate()[1]}")


@pytest.fixture
def wolfssl(require_impl: Callable[[str], Implementation]) -> Implementation:
    return require_impl("wolfssl")


@pytest.fixture
def run_pair(wolfssl: Implementation, test_pki: pki.TestPki) -> Callable[..., PairOutcome]:
    def run(
        server_args: list[str],
        client_args: list[str],
        *,
        via: Callable[[int], AbstractContextManager[int]] | None = None,
        timeout: float = RUN_TIMEOUT,
        server_env: dict[str, str] | None = None,
    ) -> PairOutcome:
        port = _free_udp_port()
        # The runner passes --opt=value; the server gets cert, key and CA, the client only the CA.
        ca = f"--ca={test_pki.ca_cert}"
        server_pki = [f"--cert={test_pki.server_cert}", f"--key={test_pki.server_key}", ca]
        base = [str(wolfssl.adapter), f"--host={HOST}"]
        server = subprocess.Popen(
            [*base, "--role=server", f"--port={port}", *server_pki, *server_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **(server_env or {})},
        )
        try:
            _wait_ready(server)
            with (via or _direct)(port) as client_port:
                client = subprocess.Popen(
                    [*base, "--role=client", f"--port={client_port}", ca, *client_args],
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


def _assert_ok(o: PairOutcome, group: str, hrr: bool, mtu: int | None = None) -> None:
    for role, side in (("client", o.client), ("server", o.server)):
        if mtu is not None:
            # --mtu is the IP path MTU: no UDP payload may exceed mtu - 48 (IPv6 + UDP headers).
            sizes = [int(n) for n in re.findall(r"\] tx (\d+)B", side.stderr)]
            assert sizes and max(sizes) <= mtu - 48, f"{role} sent {sizes}"
        assert side.rc == 0, f"{role} rc={side.rc} result={side.result}\n{side.stderr}"
        assert side.result == {
            "event": "result",
            "ok": True,
            "version": "DTLSv1.3",
            "group": group,
            "hrr": hrr,
            "error": None,
        }, f"{role}: {side.stderr}"


def _args(groups: str, mtu: int, validate: str, key_share: str | None = None) -> tuple:
    server = [f"--groups={groups}", f"--mtu={mtu}", f"--validate={validate}"]
    client = [f"--groups={groups}", f"--mtu={mtu}", f"--key-share={key_share or groups}"]
    return server, client


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_x25519_self_interop(run_pair, validate: str) -> None:
    o = run_pair(*_args("X25519", 1500, validate))
    _assert_ok(o, "X25519", hrr=validate == "cookie")


@pytest.mark.parametrize("mtu", [1500, 1280])
@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_x25519mlkem768_self_interop(run_pair, mtu: int, validate: str) -> None:
    o = run_pair(*_args("X25519MLKEM768", mtu, validate))
    # At MTU 1280 CH1 does not fit, so the client sends an empty key_share (xfail test below).
    _assert_ok(o, "X25519MLKEM768", hrr=validate == "cookie" or mtu == 1280, mtu=mtu)


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_secp256r1mlkem768_self_interop(run_pair, validate: str) -> None:
    o = run_pair(*_args("SecP256r1MLKEM768", 1500, validate))
    _assert_ok(o, "SecP256r1MLKEM768", hrr=validate == "cookie", mtu=1500)


@pytest.mark.xfail(
    strict=True,
    reason="wolfSSL 5.9.4 client (WOLFSSL_DTLS_CH_FRAG) replaces the requested key share with an "
    "empty key_share when CH1 exceeds the MTU, forcing an HRR instead of fragmenting CH1 "
    "(src/tls13.c, 'Sending empty key share so we don't fragment CH1')",
)
def test_client_sends_full_pq_share_in_fragmented_ch1(run_pair) -> None:
    o = run_pair(*_args("X25519MLKEM768", 1280, "off"))
    _assert_ok(o, "X25519MLKEM768", hrr=False, mtu=1280)


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_empty_key_share_triggers_hrr(run_pair, validate: str) -> None:
    o = run_pair(*_args("X25519MLKEM768", 1500, validate, key_share="empty"))
    _assert_ok(o, "X25519MLKEM768", hrr=True)


def test_wrong_guess_triggers_hrr(run_pair) -> None:
    server = ["--groups=X25519MLKEM768", "--mtu=1500", "--validate=off"]
    client = ["--groups=X25519,X25519MLKEM768", "--mtu=1500", "--key-share=X25519"]
    _assert_ok(run_pair(server, client), "X25519MLKEM768", hrr=True)


@pytest.mark.parametrize(
    "extra",
    [
        ["--groups", "MLKEM512X25519", "--key-share", "MLKEM512X25519"],
        ["--groups", "X25519,MLKEM768"],
        ["--psk-in", "/nonexistent"],
        ["--no-such-option"],
    ],
)
@pytest.mark.parametrize("role", ["client", "server"])
def test_unsupported_option_exits_2(
    wolfssl: Implementation, test_pki: pki.TestPki, role: str, extra: list[str]
) -> None:
    # Space-separated form here; run_pair covers --opt=value.
    cmd = [str(wolfssl.adapter), "--role", role, "--host", HOST, "--port", "9"]
    if role == "server":
        cmd += ["--cert", str(test_pki.server_cert), "--key", str(test_pki.server_key)]
    cmd += ["--ca", str(test_pki.ca_cert), *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    assert proc.returncode == 2, proc.stderr
    result = _result_line(proc.stdout)
    assert result is not None
    assert result["ok"] is False
    assert "unsupported" in result["error"]


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
    "fragment' (src/ssl_api_hs.c, src/dtls13.c)",
)
def test_server_accepts_fragmented_ch1_without_validation(run_pair) -> None:
    server, client = _args("X25519MLKEM768", 1500, "off")
    o = run_pair(server, client, via=_ch1_splitting_relay, timeout=HANG_TIMEOUT)
    _assert_ok(o, "X25519MLKEM768", hrr=False)


def test_server_accepts_fragmented_ch1_without_validation_accept_tls13(run_pair) -> None:
    server, client = _args("X25519MLKEM768", 1500, "off")
    env = {"DTLS_INTEROP_WOLFSSL_ACCEPT_TLSV13": "1"}
    o = run_pair(server, client, via=_ch1_splitting_relay, server_env=env)
    _assert_ok(o, "X25519MLKEM768", hrr=False)
    first = re.search(r"rx \d+B \| rec=22 epoch=0 hs=1 seq=0 frag=0\+(\d+)/(\d+)", o.server.stderr)
    assert first is not None and int(first[1]) < int(first[2]), o.server.stderr


@pytest.mark.xfail(
    strict=True,
    reason="wolfSSL 5.9.4 server with stateless HRR cookie (its DTLS 1.3 default) silently drops "
    "a fragmented CH1 that has no cookie in its first fragment (src/dtls13.c, "
    "Dtls13AcceptFragmented / DoClientHelloStateless); the client times out",
)
def test_server_accepts_fragmented_ch1_with_cookie(run_pair) -> None:
    server, client = _args("X25519MLKEM768", 1500, "cookie")
    o = run_pair(server, client, via=_ch1_splitting_relay, timeout=HANG_TIMEOUT)
    _assert_ok(o, "X25519MLKEM768", hrr=True)


def test_relay_split_is_well_formed() -> None:
    body = bytes(range(256)) * 4
    hs = b"\x01" + len(body).to_bytes(3) + b"\x00\x00" + b"\x00" * 3 + len(body).to_bytes(3)
    record = b"\x16\xfe\xfd\x00\x00" + (3).to_bytes(6) + (len(hs) + len(body)).to_bytes(2)
    parts = _split_ch1(record + hs + body)
    assert parts is not None
    assert [int.from_bytes(p[5:11]) for p in parts] == [6, 7]
    assert b"".join(p[25:] for p in parts) == body
