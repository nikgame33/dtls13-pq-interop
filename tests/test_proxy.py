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
    UdpProxy,
    Verdict,
    ch1_fragment_at,
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


def test_second_client_is_dropped(server: socket.socket, client: socket.socket) -> None:
    with (
        UdpProxy(server=server_addr(server)) as proxy,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other,
    ):
        client.sendto(b"first", proxy.address)
        assert server.recv(2048) == b"first"
        other.sendto(b"intruder", proxy.address)
        client.sendto(b"second", proxy.address)
        assert server.recv(2048) == b"second"
        wait_entries(proxy, 3)
    assert [(d.payload, d.action, d.reason) for d in proxy.trace] == [
        (b"first", "forwarded", None),
        (b"intruder", "dropped", "unexpected source"),
        (b"second", "forwarded", None),
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
