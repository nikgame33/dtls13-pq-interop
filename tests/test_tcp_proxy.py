"""TCP proxy tests over real loopback TCP sockets."""

from __future__ import annotations

import gc
import os
import socket
import threading
from collections.abc import Iterator

import pytest

from dtls_interop.tcp_proxy import Segment, TcpProxy

pytestmark = [
    pytest.mark.filterwarnings("error::ResourceWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

TIMEOUT = 5.0


@pytest.fixture
def listener() -> Iterator[socket.socket]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        s.settimeout(TIMEOUT)
        yield s


def connect(address: tuple[str, int]) -> socket.socket:
    s = socket.create_connection(address, timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    return s


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk, f"EOF after {data!r}"
        data += chunk
    return data


def wait_entries(proxy: TcpProxy, n: int) -> list[Segment]:
    assert proxy.wait_for(lambda t: len(t) >= n, TIMEOUT), proxy.trace
    return proxy.trace


def stream(trace: list[Segment], flow: int, direction: str) -> bytes:
    return b"".join(s.payload for s in trace if s.flow == flow and s.direction == direction)


def test_relays_both_directions_and_half_close(listener: socket.socket) -> None:
    with TcpProxy(listener.getsockname()) as proxy:
        host, port = proxy.address
        assert host == "127.0.0.1" and port != 0
        with connect(proxy.address) as client:
            server, _ = listener.accept()
            with server:
                server.settimeout(TIMEOUT)
                client.sendall(b"hello")
                assert recv_exactly(server, 5) == b"hello"
                server.sendall(b"world" * 1000)
                assert recv_exactly(client, 5000) == b"world" * 1000
                client.shutdown(socket.SHUT_WR)
                assert server.recv(10) == b""  # the client's FIN arrives as a FIN
                server.sendall(b"after half-close")
                assert recv_exactly(client, 16) == b"after half-close"
                server.shutdown(socket.SHUT_WR)
                assert client.recv(10) == b""
                assert proxy.wait_for(lambda t: sum(s.action == "closed" for s in t) == 2, TIMEOUT)
    trace = proxy.trace
    assert stream(trace, 0, "c2s") == b"hello"
    assert stream(trace, 0, "s2c") == b"world" * 1000 + b"after half-close"
    assert [(s.direction, s.action) for s in trace if s.action != "forwarded"] == [
        ("c2s", "closed"),
        ("s2c", "closed"),
    ]
    assert [s.index for s in trace] == list(range(len(trace)))
    assert all(s.size == len(s.payload) for s in trace)


def test_each_connection_is_a_flow(listener: socket.socket) -> None:
    with TcpProxy(listener.getsockname()) as proxy:
        for i in range(2):
            with connect(proxy.address) as client:
                server, _ = listener.accept()
                with server:
                    client.sendall(b"conn %d" % i)
                    assert recv_exactly(server, 6) == b"conn %d" % i
        wait_entries(proxy, 2)
    assert [(s.flow, s.payload) for s in proxy.trace if s.payload] == [
        (0, b"conn 0"),
        (1, b"conn 1"),
    ]


def test_no_server_closes_the_client() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
        unused.bind(("127.0.0.1", 0))
        address = unused.getsockname()
    with TcpProxy(address) as proxy, connect(proxy.address) as client:
        assert client.recv(10) == b""
    assert proxy.trace == []


def open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc")
def test_exit_with_open_connections_closes_everything(listener: socket.socket) -> None:
    gc.collect()
    fds, threads = open_fds(), threading.active_count()
    with TcpProxy(listener.getsockname()) as proxy, connect(proxy.address) as client:
        server, _ = listener.accept()
        with server:
            client.sendall(b"x")
            assert server.recv(1) == b"x"
    assert threading.active_count() == threads
    assert open_fds() == fds
