"""The runner's default path: proxy rules from PathConditions and the trace summary (real UDP)."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from dtls_interop import path, scenarios
from dtls_interop.proxy import (
    Datagram,
    DropOnce,
    ReorderClientHelloFragments,
    SplitClientHello,
)
from dtls_interop.scenarios import Impairment, PathConditions

TIMEOUT = 5.0
CH_LEN = 1400


def ch_record(offset: int, size: int, *, record_seq: int, message_seq: int = 0) -> bytes:
    """A DTLSPlaintext record with one fragment of a CH_LEN-byte ClientHello."""
    hs = (
        b"\x01"
        + CH_LEN.to_bytes(3)
        + message_seq.to_bytes(2)
        + offset.to_bytes(3)
        + size.to_bytes(3)
        + bytes([0x5A]) * size
    )
    return b"\x16\xfe\xfd\x00\x00" + record_seq.to_bytes(6) + len(hs).to_bytes(2) + hs


@pytest.fixture
def server() -> Iterator[socket.socket]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        s.settimeout(TIMEOUT)
        yield s


@pytest.fixture
def client() -> Iterator[socket.socket]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        yield s


def exchange(conditions: PathConditions, server, client, datagrams, expect: int) -> list[Datagram]:
    """Send datagrams through proxy_path, receive `expect` at the server, return the trace.

    The proxy handles datagrams in order and exit joins its thread, so the trace is complete.
    """
    with path.proxy_path(server.getsockname(), conditions) as proxy:
        for d in datagrams:
            client.sendto(d, proxy.address)
        for _ in range(expect):
            server.recv(4096)
    return proxy.trace


def test_rules_follow_the_conditions_with_the_split_first():
    assert path.rules(PathConditions(pmtu=1280)) == []
    s09 = scenarios.get("S09+split").path
    split, drop = path.rules(s09)
    assert isinstance(split, SplitClientHello) and isinstance(drop, DropOnce)
    [reorder] = path.rules(scenarios.get("S08").path)
    assert isinstance(reorder, ReorderClientHelloFragments)


def test_unknown_impairment_is_refused():
    with pytest.raises(ValueError, match="unknown impairment"):
        path.rules(PathConditions(pmtu=1280, impairments=("teleport",)))  # type: ignore[arg-type]


def test_split_and_drop_are_told_apart_from_what_the_client_sent(server, client):
    whole = ch_record(0, CH_LEN, record_seq=0)
    retransmission = ch_record(0, CH_LEN, record_seq=1)
    trace = exchange(
        scenarios.get("S09+split").path, server, client, [whole, retransmission], expect=3
    )

    summary = path.summarize(trace)
    assert summary.ch1 == path.ClientHelloSummary(size=CH_LEN, fragments=1)
    assert summary.ch2 is None
    assert summary.actions == {
        "dropped: drop first CH1 fragment": 1,
        "replaced: split CH1 into 2 fragments": 2,
    }


def test_client_fragments_and_reorder(server, client):
    first, second = ch_record(0, 1000, record_seq=0), ch_record(1000, 400, record_seq=1)
    ch2 = ch_record(0, CH_LEN, record_seq=2, message_seq=1)
    conditions = PathConditions(pmtu=1500, impairments=(Impairment.REORDER_CH1,))
    trace = exchange(conditions, server, client, [first, second, first, ch2], expect=4)

    summary = path.summarize(trace)
    # The retransmitted first fragment is not counted again.
    assert summary.ch1 == path.ClientHelloSummary(size=CH_LEN, fragments=2)
    assert summary.ch2 == path.ClientHelloSummary(size=CH_LEN, fragments=1)
    assert summary.actions == {"delayed: reorder CH1 fragments": 2}


def test_pmtu_drops_are_counted(server, client):
    big = ch_record(0, CH_LEN, record_seq=0)
    small = ch_record(0, 100, record_seq=1, message_seq=1)
    trace = exchange(PathConditions(pmtu=1280), server, client, [big, small], expect=1)

    summary = path.summarize(trace)
    assert summary.actions == {"dropped: exceeds pmtu": 1}
    # The client sent CH1, even though the path lost it.
    assert summary.ch1 == path.ClientHelloSummary(size=CH_LEN, fragments=1)


def test_summary_ignores_foreign_trace_entries():
    assert path.summarize([object()]) == path.TraceSummary(ch1=None, ch2=None, actions={})
