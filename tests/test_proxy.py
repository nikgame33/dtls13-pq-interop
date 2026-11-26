"""End-to-end proxy tests over real loopback UDP sockets."""

from __future__ import annotations

import gc
import os
import socket
import threading
from collections.abc import Iterator

import pytest

from dtls_interop.proxy import (
    IPV6_UDP_OVERHEAD,
    Datagram,
    DropOnce,
    Packet,
    ReorderClientHelloFragments,
    Rule,
    SplitClientHello,
    UdpProxy,
    Verdict,
    ch1_fragment_at,
)
from dtls_interop.records import (
    PlaintextRecord,
    encode_ack,
    parse_ack,
    parse_datagram,
    reassemble,
)

pytestmark = [
    pytest.mark.filterwarnings("error::ResourceWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

TIMEOUT = 5.0
CH1_LEN = 1500


def ch_fragment(offset: int, size: int, *, seq: int = 0, record_seq: int = 0) -> bytes:
    """A DTLSPlaintext handshake record with one ClientHello fragment of a CH1_LEN-byte message."""
    body = bytes([0x5A]) * size
    hs = (
        b"\x01"
        + CH1_LEN.to_bytes(3)
        + seq.to_bytes(2)
        + offset.to_bytes(3)
        + size.to_bytes(3)
        + body
    )
    return b"\x16\xfe\xfd\x00\x00" + record_seq.to_bytes(6) + len(hs).to_bytes(2) + hs


FRAG0 = ch_fragment(0, 1000)
FRAG1 = ch_fragment(1000, 500, record_seq=1)


@pytest.fixture
def server() -> Iterator[socket.socket]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        s.settimeout(TIMEOUT)
        yield s


@pytest.fixture
def client() -> Iterator[socket.socket]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        s.settimeout(TIMEOUT)
        yield s


def server_addr(server: socket.socket) -> tuple[str, int]:
    return server.getsockname()


def wait_entries(proxy: UdpProxy, n: int) -> list[Datagram]:
    assert proxy.wait_for(lambda t: len(t) >= n, TIMEOUT), proxy.trace
    return proxy.trace


def test_forwards_both_directions_and_traces(server: socket.socket, client: socket.socket) -> None:
    with UdpProxy(server=server_addr(server), pmtu=1280) as proxy:
        host, port = proxy.address
        assert host == "127.0.0.1" and port != 0
        client.sendto(b"hello", proxy.address)
        data, upstream = server.recvfrom(2048)
        assert data == b"hello"
        server.sendto(b"world", upstream)
        assert client.recvfrom(2048) == (b"world", proxy.address)
        client.sendto(FRAG0, proxy.address)
        assert server.recv(2048) == FRAG0
        wait_entries(proxy, 3)
    trace = proxy.trace
    assert [(d.index, d.direction, d.size, d.payload, d.action, d.reason) for d in trace] == [
        (0, "c2s", 5, b"hello", "forwarded", None),
        (1, "s2c", 5, b"world", "forwarded", None),
        (2, "c2s", len(FRAG0), FRAG0, "forwarded", None),
    ]
    times = [d.time for d in trace]
    assert times == sorted(times) and times[0] >= 0


def test_pmtu_drops_oversize_in_both_directions(
    server: socket.socket, client: socket.socket
) -> None:
    limit = 1280 - IPV6_UDP_OVERHEAD
    with UdpProxy(server=server_addr(server), pmtu=1280) as proxy:
        assert proxy.max_payload == limit == 1232
        client.sendto(b"a" * (limit + 1), proxy.address)
        client.sendto(b"b" * limit, proxy.address)
        data, upstream = server.recvfrom(4096)
        assert data == b"b" * limit  # the oversize datagram never arrived before it
        server.sendto(b"c" * (limit + 1), upstream)
        server.sendto(b"d" * limit, upstream)
        assert client.recv(4096) == b"d" * limit
        wait_entries(proxy, 4)
    assert [(d.size, d.action, d.reason) for d in proxy.trace] == [
        (limit + 1, "dropped", "exceeds pmtu"),
        (limit, "forwarded", None),
        (limit + 1, "dropped", "exceeds pmtu"),
        (limit, "forwarded", None),
    ]


def test_pmtu_none_disables_limit(server: socket.socket, client: socket.socket) -> None:
    with UdpProxy(server=server_addr(server), pmtu=None) as proxy:
        client.sendto(b"x" * 9000, proxy.address)
        assert server.recv(65535) == b"x" * 9000


def test_drop_once_drops_first_ch1_fragment_only(
    server: socket.socket, client: socket.socket
) -> None:
    rule = DropOnce(ch1_fragment_at(0), reason="lose first CH1 fragment")
    with UdpProxy(server=server_addr(server), rules=[rule]) as proxy:
        client.sendto(FRAG0, proxy.address)
        client.sendto(FRAG1, proxy.address)
        client.sendto(FRAG0, proxy.address)  # the client's retransmission
        assert server.recv(4096) == FRAG1
        assert server.recv(4096) == FRAG0
        wait_entries(proxy, 3)
    assert [(d.index, d.action, d.reason) for d in proxy.trace] == [
        (0, "dropped", "lose first CH1 fragment"),
        (1, "forwarded", None),
        (2, "forwarded", None),
    ]


def test_reorder_releases_ch1_fragments_in_reverse(
    server: socket.socket, client: socket.socket
) -> None:
    ch2 = ch_fragment(0, 1000, seq=1)
    with UdpProxy(server=server_addr(server), rules=[ReorderClientHelloFragments()]) as proxy:
        client.sendto(FRAG0, proxy.address)
        client.sendto(b"not dtls", proxy.address)
        client.sendto(FRAG1, proxy.address)
        assert server.recv(4096) == b"not dtls"
        assert server.recv(4096) == FRAG1
        assert server.recv(4096) == FRAG0
        client.sendto(FRAG0, proxy.address)  # acts once: retransmissions pass unchanged
        client.sendto(ch2, proxy.address)
        assert server.recv(4096) == FRAG0
        assert server.recv(4096) == ch2
        wait_entries(proxy, 5)
    trace = proxy.trace
    assert [(d.index, d.action) for d in trace] == [
        (1, "forwarded"),
        (2, "delayed"),
        (0, "delayed"),
        (3, "forwarded"),
        (4, "forwarded"),
    ]
    assert trace[1].reason is not None and trace[1].reason.startswith("reorder CH1 fragments")


def test_reorder_leaves_unfragmented_ch1_alone(
    server: socket.socket, client: socket.socket
) -> None:
    whole = ch_fragment(0, CH1_LEN)
    with UdpProxy(
        server=server_addr(server), pmtu=None, rules=[ReorderClientHelloFragments()]
    ) as proxy:
        client.sendto(whole, proxy.address)
        assert server.recv(4096) == whole
        wait_entries(proxy, 1)
    assert proxy.trace[0].action == "forwarded"


def test_reorder_releases_incomplete_ch1_after_timeout(
    server: socket.socket, client: socket.socket
) -> None:
    timeout = 0.05
    rule = ReorderClientHelloFragments(timeout=timeout)
    with UdpProxy(server=server_addr(server), rules=[rule]) as proxy:
        client.sendto(FRAG0, proxy.address)
        assert server.recv(4096) == FRAG0
        wait_entries(proxy, 1)
    (entry,) = proxy.trace
    assert entry.action == "delayed"
    assert entry.time >= timeout


def test_released_packets_continue_through_later_rules(
    server: socket.socket, client: socket.socket
) -> None:
    rules = [ReorderClientHelloFragments(), DropOnce(ch1_fragment_at(0))]
    with UdpProxy(server=server_addr(server), rules=rules) as proxy:
        client.sendto(FRAG0, proxy.address)
        client.sendto(FRAG1, proxy.address)
        client.sendto(b"marker", proxy.address)
        assert server.recv(4096) == FRAG1
        assert server.recv(4096) == b"marker"
        wait_entries(proxy, 3)
    assert {d.index: d.action for d in proxy.trace} == {0: "dropped", 1: "delayed", 2: "forwarded"}


def test_each_client_address_is_its_own_flow(server: socket.socket, client: socket.socket) -> None:
    # A resumed second connection (ADR 0004) comes from a new port and must reach the server
    # from a new port too, as it would without the proxy.
    with (
        UdpProxy(server=server_addr(server)) as proxy,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other,
    ):
        other.settimeout(TIMEOUT)
        client.sendto(b"first", proxy.address)
        data, upstream1 = server.recvfrom(2048)
        assert data == b"first"
        other.sendto(b"second", proxy.address)
        data, upstream2 = server.recvfrom(2048)
        assert data == b"second" and upstream2 != upstream1
        server.sendto(b"to second", upstream2)
        server.sendto(b"to first", upstream1)
        assert other.recvfrom(2048) == (b"to second", proxy.address)
        assert client.recvfrom(2048) == (b"to first", proxy.address)
        client.sendto(b"first again", proxy.address)
        assert server.recvfrom(2048) == (b"first again", upstream1)
        wait_entries(proxy, 5)
    assert [(d.payload, d.direction, d.flow, d.action) for d in proxy.trace] == [
        (b"first", "c2s", 0, "forwarded"),
        (b"second", "c2s", 1, "forwarded"),
        (b"to second", "s2c", 1, "forwarded"),
        (b"to first", "s2c", 0, "forwarded"),
        (b"first again", "c2s", 0, "forwarded"),
    ]


def open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc")
def test_exit_closes_sockets_joins_thread_and_records_held(
    server: socket.socket, client: socket.socket
) -> None:
    gc.collect()
    fds = open_fds()
    threads = threading.active_count()
    with UdpProxy(server=server_addr(server), rules=[ReorderClientHelloFragments(60)]) as proxy:
        assert threading.active_count() == threads + 1
        client.sendto(FRAG0, proxy.address)
        # The hold is invisible in the trace, so prove arrival with a forwarded marker behind it.
        client.sendto(b"marker", proxy.address)
        assert server.recv(4096) == b"marker"
    assert threading.active_count() == threads
    assert open_fds() == fds
    assert [(d.index, d.action, d.reason) for d in proxy.trace] == [
        (1, "forwarded", None),
        (0, "dropped", "reorder CH1 fragments; held at exit"),
    ]


class Boom(Rule):
    def on_packet(self, packet: Packet, now: float) -> Verdict:
        raise ValueError("boom")


def test_rule_failure_surfaces_on_exit(server: socket.socket, client: socket.socket) -> None:
    with (
        pytest.raises(RuntimeError, match="proxy thread failed") as info,
        UdpProxy(server=server_addr(server), rules=[Boom()]) as proxy,
    ):
        client.sendto(b"x", proxy.address)
        thread = proxy._thread
        assert thread is not None
        thread.join(TIMEOUT)  # let the failure happen before exit wakes the thread
        assert not thread.is_alive()
    assert isinstance(info.value.__cause__, ValueError)


# --- SplitClientHello ---------------------------------------------------------------------------

PQ_CH1_BODY = bytes(
    i % 251 for i in range(1400)
)  # about a ClientHello with an X25519MLKEM768 share


def handshake_record(body: bytes, *, record_seq: int, message_seq: int = 0) -> bytes:
    """One DTLSPlaintext record with one unfragmented ClientHello-type handshake message."""
    size = len(body).to_bytes(3)
    hs = b"\x01" + size + message_seq.to_bytes(2) + bytes(3) + size + body
    return b"\x16\xfe\xfd\x00\x00" + record_seq.to_bytes(6) + len(hs).to_bytes(2) + hs


def ack_record(numbers: list[tuple[int, int]], *, record_seq: int = 0) -> bytes:
    body = encode_ack(numbers)
    return b"\x1a\xfe\xfd\x00\x00" + record_seq.to_bytes(6) + len(body).to_bytes(2) + body


def single_record(payload: bytes) -> PlaintextRecord:
    parsed = parse_datagram(payload)
    assert parsed.error is None
    (record,) = parsed.records
    assert isinstance(record, PlaintextRecord)
    return record


def test_split_ch1_into_fragments_that_reassemble(
    server: socket.socket, client: socket.socket
) -> None:
    ch1 = handshake_record(PQ_CH1_BODY, record_seq=0)
    assert len(ch1) > 1280 - IPV6_UDP_OVERHEAD
    with UdpProxy(server=server_addr(server), pmtu=1280, rules=[SplitClientHello(3)]) as proxy:
        client.sendto(ch1, proxy.address)
        received = [server.recv(4096) for _ in range(3)]
        wait_entries(proxy, 4)
    records = [single_record(d) for d in received]
    assert [r.sequence_number for r in records] == [0, 1, 2]
    frags = [f for r in records for f in r.handshake]
    assert [(f.message_seq, f.length) for f in frags] == [(0, 1400)] * 3
    spans = [(f.fragment_offset, f.fragment_length) for f in frags]
    assert spans == [(0, 466), (466, 467), (933, 467)]
    assert reassemble(frags) == PQ_CH1_BODY
    assert [(d.index, d.action, d.origin) for d in proxy.trace] == [
        (0, "replaced", None),
        (1, "forwarded", 0),
        (2, "forwarded", 0),
        (3, "forwarded", 0),
    ]
    assert proxy.trace[0].payload == ch1
    assert proxy.trace[0].reason == "split CH1 into 3 fragments"
    assert [d.payload for d in proxy.trace[1:]] == received


def test_split_renumbers_client_epoch0_records_monotonically(
    server: socket.socket, client: socket.socket
) -> None:
    ch1 = handshake_record(PQ_CH1_BODY, record_seq=0)
    retransmission = handshake_record(PQ_CH1_BODY, record_seq=1)
    ch2 = handshake_record(PQ_CH1_BODY[:300], record_seq=2, message_seq=1)
    fragmented = ch_fragment(0, 1000, seq=0, record_seq=3)  # already fragmented: not split again
    with UdpProxy(server=server_addr(server), pmtu=1280, rules=[SplitClientHello()]) as proxy:
        for datagram in (ch1, retransmission, ch2, fragmented):
            client.sendto(datagram, proxy.address)
        received = [server.recv(4096) for _ in range(6)]
        wait_entries(proxy, 10)
    # Client seq n becomes 2n + i: unique and increasing, as the server's replay window requires.
    assert [single_record(d).sequence_number for d in received] == [0, 1, 2, 3, 4, 6]
    assert single_record(received[4]).fragment == single_record(ch2).fragment
    assert single_record(received[5]).fragment == single_record(fragmented).fragment
    replaced = [(d.index, d.reason) for d in proxy.trace if d.action == "replaced"]
    assert replaced == [
        (0, "split CH1 into 2 fragments"),
        (3, "split CH1 into 2 fragments"),
        (6, "renumber client epoch 0 records"),
        (8, "renumber client epoch 0 records"),
    ]


def test_split_maps_server_acks_back_to_client_records(
    server: socket.socket, client: socket.socket
) -> None:
    with UdpProxy(server=server_addr(server), rules=[SplitClientHello()]) as proxy:
        client.sendto(handshake_record(PQ_CH1_BODY, record_seq=0), proxy.address)
        _, upstream = server.recvfrom(4096)
        server.recv(4096)
        cases = [
            ([(0, 0)], ()),  # one piece of client record 0 is not the whole record
            ([(0, 0), (0, 1)], ((0, 0),)),
            ([(0, 1), (2, 7)], ((2, 7),)),
        ]
        for server_numbers, client_numbers in cases:
            server.sendto(ack_record(server_numbers), upstream)
            assert parse_ack(single_record(client.recv(4096)).fragment) == client_numbers
        client.sendto(handshake_record(b"x" * 50, record_seq=1, message_seq=1), proxy.address)
        server.recv(4096)
        server.sendto(ack_record([(0, 2)]), upstream)  # renumbered client record 1 is 2
        assert parse_ack(single_record(client.recv(4096)).fragment) == ((0, 1),)
        alert = b"\x15\xfe\xfd" + bytes(8) + b"\x00\x02\x02\x28"
        server.sendto(alert, upstream)
        assert client.recv(4096) == alert
        wait_entries(proxy, 14)
    s2c = [d for d in proxy.trace if d.direction == "s2c"]
    assert [d.action for d in s2c] == ["replaced", "forwarded"] * 4 + ["forwarded"]
    assert {d.reason for d in s2c if d.action == "replaced"} == {"map ACK record numbers back"}


def test_pmtu_applies_to_split_fragments_not_the_original(
    server: socket.socket, client: socket.socket
) -> None:
    ch1 = handshake_record(PQ_CH1_BODY, record_seq=0)
    huge = handshake_record(bytes(3000), record_seq=1)
    with UdpProxy(server=server_addr(server), pmtu=1280, rules=[SplitClientHello()]) as proxy:
        client.sendto(ch1, proxy.address)
        client.sendto(huge, proxy.address)
        client.sendto(b"marker", proxy.address)
        assert len(server.recv(4096)) <= proxy.max_payload
        assert len(server.recv(4096)) <= proxy.max_payload
        assert server.recv(4096) == b"marker"  # both 1.5 KB halves of the huge CH1 were dropped
        wait_entries(proxy, 7)
    assert [(d.index, d.action, d.reason, d.origin) for d in proxy.trace[3:6]] == [
        (3, "replaced", "split CH1 into 2 fragments", None),
        (4, "dropped", "exceeds pmtu", 3),
        (5, "dropped", "exceeds pmtu", 3),
    ]


def test_split_fragments_pass_through_later_rules(
    server: socket.socket, client: socket.socket
) -> None:
    rules = [SplitClientHello(), ReorderClientHelloFragments()]
    with UdpProxy(server=server_addr(server), pmtu=1280, rules=rules) as proxy:
        client.sendto(handshake_record(PQ_CH1_BODY, record_seq=0), proxy.address)
        offsets = [single_record(server.recv(4096)).handshake[0].fragment_offset for _ in range(2)]
        wait_entries(proxy, 3)
    assert offsets == [700, 0]
    assert [(d.index, d.action, d.origin) for d in proxy.trace] == [
        (0, "replaced", None),
        (2, "delayed", 0),
        (1, "delayed", 0),
    ]


def test_split_rejects_fewer_than_two_fragments() -> None:
    with pytest.raises(ValueError, match="at least 2"):
        SplitClientHello(1)
