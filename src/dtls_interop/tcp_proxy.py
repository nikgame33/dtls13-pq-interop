"""Userspace TCP relay between TLS clients and one server on loopback (ADR 0004).

The TLS counterpart of the UDP proxy: it passes both byte streams on unchanged and records each
chunk it reads, so the trace shows what each endpoint sent. It has no impairments and no PMTU.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

Direction = Literal["c2s", "s2c"]

_RECV_SIZE = 65536
_JOIN_TIMEOUT = 5.0


@dataclass(frozen=True)
class Segment:
    """One trace entry: the bytes one read returned, or the end of one direction.

    ``flow`` numbers the accepted client connections from 0. "closed" (the sender shut down its
    side) and "reset" (the connection broke) carry an empty payload.
    """

    index: int
    time: float  # seconds since proxy start
    flow: int
    direction: Direction
    size: int
    payload: bytes
    action: Literal["forwarded", "closed", "reset"]


class TcpProxy:
    """Relay every accepted client connection over its own connection to ``server``."""

    def __init__(self, server: tuple[str, int]) -> None:
        self._server = server
        self._trace: list[Segment] = []
        self._cond = threading.Condition()
        self._lock = threading.Lock()  # guards _sockets, _threads and _stopping
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stopping = False
        self._errors: list[BaseException] = []
        self._start = 0.0

    @property
    def address(self) -> tuple[str, int]:
        """Where the client connects to."""
        host, port = self._listener.getsockname()[:2]
        return host, port

    @property
    def trace(self) -> list[Segment]:
        with self._cond:
            return list(self._trace)

    def wait_for(self, predicate: Callable[[list[Segment]], bool], timeout: float) -> bool:
        """Block until ``predicate(trace)`` holds or ``timeout`` passes; returns the outcome."""
        with self._cond:
            return self._cond.wait_for(lambda: predicate(self._trace), timeout)

    def __enter__(self) -> TcpProxy:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._listener.bind(("127.0.0.1", 0))
            self._listener.listen()
            self._start = time.monotonic()
            self._spawn(self._accept_loop, "tcp-proxy-accept")
        except BaseException:
            self._listener.close()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        with self._lock:
            self._stopping = True
            sockets, threads = list(self._sockets), list(self._threads)
        # shutdown wakes threads blocked in accept or recv on these sockets.
        for sock in [self._listener, *sockets]:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        for thread in threads:
            thread.join(_JOIN_TIMEOUT)
        alive = any(t.is_alive() for t in threads)
        self._listener.close()
        for sock in sockets:
            sock.close()
        if alive:
            raise RuntimeError("TCP proxy thread did not stop")
        if self._errors and exc_info[0] is None:
            raise RuntimeError("TCP proxy thread failed") from self._errors[0]

    def _spawn(self, target: Callable[..., None], name: str, *args: object) -> None:
        def run() -> None:
            try:
                target(*args)
            except BaseException as exc:
                self._errors.append(exc)

        thread = threading.Thread(target=run, name=name, daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()

    def _record(self, flow: int, direction: Direction, payload: bytes, action: str) -> None:
        with self._cond:
            now = time.monotonic() - self._start
            entry = Segment(len(self._trace), now, flow, direction, len(payload), payload, action)  # type: ignore[arg-type]
            self._trace.append(entry)
            self._cond.notify_all()

    def _accept_loop(self) -> None:
        flow = 0
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return  # the listener was shut down
            upstream = socket.socket(socket.AF_INET6 if ":" in self._server[0] else socket.AF_INET)
            with self._lock:
                if self._stopping:
                    client.close()
                    upstream.close()
                    return
                self._sockets += [client, upstream]
            try:
                upstream.connect(self._server)
            except OSError:
                client.close()  # as with no server: the client sees its connection end
                continue
            for sock in (client, upstream):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._spawn(self._pipe, f"tcp-proxy-{flow}-c2s", flow, "c2s", client, upstream)
            self._spawn(self._pipe, f"tcp-proxy-{flow}-s2c", flow, "s2c", upstream, client)
            flow += 1

    def _pipe(
        self, flow: int, direction: Direction, src: socket.socket, dst: socket.socket
    ) -> None:
        """Copy src to dst until src ends; a FIN is passed on as a FIN, an error ends the flow."""
        while True:
            try:
                data = src.recv(_RECV_SIZE)
            except OSError:
                self._record(flow, direction, b"", "reset")
                _end(src, dst)
                return
            if not data:
                self._record(flow, direction, b"", "closed")
                with contextlib.suppress(OSError):
                    dst.shutdown(socket.SHUT_WR)
                return
            self._record(flow, direction, data, "forwarded")
            try:
                dst.sendall(data)
            except OSError:
                self._record(flow, direction, b"", "reset")
                _end(src, dst)
                return


def _end(*sockets: socket.socket) -> None:
    # Sockets are closed only at proxy exit, so the other pipe thread never sees a reused fd.
    for sock in sockets:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
