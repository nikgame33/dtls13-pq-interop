"""Trace analysis tests: ClientHello/HRR cookie echo per flow, for DTLS and TLS traces."""

from __future__ import annotations

from test_records import ext, hello_retry_request, hs_fragment, plaintext, u8, u16

from dtls_interop.hello_trace import cookie_echoed, dtls_flows, tls_flows, trace_flows
from dtls_interop.proxy import Datagram
from dtls_interop.records import HRR_RANDOM, parse_hello, parse_tls_handshake
from dtls_interop.tcp_proxy import Segment

COOKIE = bytes(range(40))


def cookie(data: bytes) -> bytes:
    return ext(44, u16(len(data)) + data)


def tls_client_hello(*extensions: bytes) -> bytes:
    exts = b"".join(extensions)
    # TLS has no legacy_cookie (RFC 9846 sec 4.2.2), unlike the DTLS ClientHello.
    body = u16(0x0303) + bytes(32) + u8(0) + u16(2) + u16(0x1301) + u8(1) + u8(0)
    return body + u16(len(exts)) + exts


def tls_hrr(*extensions: bytes) -> bytes:
    exts = b"".join(extensions)
    return u16(0x0303) + HRR_RANDOM + u8(0) + u16(0x1301) + u8(0) + u16(len(exts)) + exts


def tls_records(msg_type: int, body: bytes, split: int | None = None) -> bytes:
    """One handshake message in TLS records, split across two records at ``split``."""
    hs = u8(msg_type) + len(body).to_bytes(3) + body
    parts = [hs] if split is None else [hs[:split], hs[split:]]
    return b"".join(u8(22) + u16(0x0303) + u16(len(p)) + p for p in parts)


CCS = u8(20) + u16(0x0303) + u16(1) + b"\x01"
ENCRYPTED = u8(23) + u16(0x0303) + u16(4) + b"\xde\xad\xbe\xef"


def test_tls_client_hello_has_no_legacy_cookie() -> None:
    hello = parse_hello(1, tls_client_hello(cookie(COOKIE)), dtls=False)
    assert hello is not None and not hello.partial
    assert hello.cookie and hello.cookie_data == COOKIE


def test_tls_stream_spanning_records_and_ccs() -> None:
    stream = (
        tls_records(1, tls_client_hello(), split=30)
        + CCS
        + tls_records(1, tls_client_hello(cookie(COOKIE)))
        + ENCRYPTED
        + b"\x17garbage after encryption"
    )
    parsed = parse_tls_handshake(stream)
    assert parsed.error is None
    assert [m.msg_type for m in parsed.messages] == [1, 1]
    assert [m.hello.cookie_data for m in parsed.messages if m.hello] == [None, COOKIE]


def test_truncated_tls_stream_reports_error() -> None:
    stream = tls_records(1, tls_client_hello())
    parsed = parse_tls_handshake(stream[:-10])
    assert parsed.messages == () and parsed.error is not None


def segments(flow: int, c2s: bytes, s2c: bytes, start: int = 0) -> list[Segment]:
    return [
        Segment(start, 0.0, flow, "c2s", len(c2s), c2s, "forwarded"),
        Segment(start + 1, 0.0, flow, "s2c", len(s2c), s2c, "forwarded"),
    ]


def tls_flow(ch2_cookie: bytes | None, flow: int = 0, start: int = 0) -> list[Segment]:
    ch2 = tls_client_hello(cookie(ch2_cookie)) if ch2_cookie is not None else tls_client_hello()
    c2s = tls_records(1, tls_client_hello()) + CCS + tls_records(1, ch2) + ENCRYPTED
    s2c = tls_records(2, tls_hrr(cookie(COOKIE))) + CCS + ENCRYPTED
    return segments(flow, c2s, s2c, start)


def test_tls_cookie_echo_per_flow() -> None:
    assert [f.cookie_echoed for f in tls_flows(tls_flow(COOKIE))] == [True]
    assert [f.cookie_echoed for f in tls_flows(tls_flow(None))] == [False]
    assert [f.cookie_echoed for f in tls_flows(tls_flow(COOKIE[::-1]))] == [False]
    both = tls_flow(COOKIE) + tls_flow(None, flow=1, start=2)
    assert cookie_echoed(tls_flows(both)) is False
    assert cookie_echoed(tls_flows(tls_flow(COOKIE) + tls_flow(COOKIE, 1, 2))) is True


def test_tls_without_hrr_says_nothing() -> None:
    c2s = tls_records(1, tls_client_hello()) + ENCRYPTED
    s2c = tls_records(2, tls_hrr()[:2] + bytes(32) + tls_hrr()[34:]) + ENCRYPTED  # a ServerHello
    (flow,) = tls_flows(segments(0, c2s, s2c))
    assert flow.hrr is None and flow.cookie_echoed is None
    assert cookie_echoed([flow]) is None


def dg(index: int, direction: str, payload: bytes, flow: int = 0, origin: int | None = None):
    return Datagram(index, 0.0, direction, len(payload), payload, "forwarded", None, origin, flow)  # type: ignore[arg-type]


def dtls_ch(*extensions: bytes) -> bytes:
    from test_records import client_hello

    return client_hello(*extensions)


def test_dtls_cookie_echo_with_fragmented_ch2() -> None:
    ch2 = dtls_ch(cookie(COOKIE), ext(0xFFAA, bytes(900)))
    trace = [
        dg(0, "c2s", plaintext(22, hs_fragment(1, dtls_ch()))),
        dg(1, "s2c", plaintext(22, hs_fragment(2, hello_retry_request(cookie(COOKIE))))),
        dg(2, "c2s", plaintext(22, hs_fragment(1, ch2, seq=1, size=500), seq=1)),
        dg(3, "c2s", plaintext(22, hs_fragment(1, ch2, seq=1, offset=500), seq=2)),
    ]
    (flow,) = dtls_flows(trace)
    assert len(flow.client_hellos) == 2 and flow.hrr is not None
    assert flow.cookie_echoed is True
    assert trace_flows(trace) == [flow]


def test_dtls_rule_emitted_datagrams_are_ignored() -> None:
    # A proxy rule's rewritten copy must not count as something the client sent.
    trace = [
        dg(0, "c2s", plaintext(22, hs_fragment(1, dtls_ch()))),
        dg(1, "s2c", plaintext(22, hs_fragment(2, hello_retry_request(cookie(COOKIE))))),
        dg(2, "c2s", plaintext(22, hs_fragment(1, dtls_ch(cookie(b"x")), seq=1)), origin=0),
        dg(3, "c2s", plaintext(22, hs_fragment(1, dtls_ch(cookie(COOKIE)), seq=1))),
    ]
    assert cookie_echoed(dtls_flows(trace)) is True


def test_dtls_flows_are_separate() -> None:
    trace = [
        dg(0, "c2s", plaintext(22, hs_fragment(1, dtls_ch())), flow=0),
        dg(1, "c2s", plaintext(22, hs_fragment(1, dtls_ch())), flow=1),
        dg(2, "s2c", plaintext(22, hs_fragment(2, hello_retry_request(cookie(COOKIE)))), flow=1),
        dg(3, "c2s", plaintext(22, hs_fragment(1, dtls_ch(), seq=1)), flow=1),
    ]
    flows = dtls_flows(trace)
    assert [(f.flow, f.cookie_echoed) for f in flows] == [(0, None), (1, False)]


def test_unknown_trace_kind_is_not_analysed() -> None:
    assert trace_flows([object()]) is None
