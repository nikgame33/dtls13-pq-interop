"""Userspace UDP proxy between one client and one server on loopback (ADR 0001).

Applies impairment rules on parsed DTLS records, then enforces the PMTU on every datagram it
sends, and records each datagram in a trace.
"""

from __future__ import annotations

import itertools
import selectors
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal

from dtls_interop.records import (
    CONTENT_ACK,
    CONTENT_HANDSHAKE,
    HS_CLIENT_HELLO,
    MAX_SEQUENCE_NUMBER,
    HandshakeFragment,
    ParsedDatagram,
    PlaintextRecord,
    Record,
    RecordNumber,
    covered,
    encode_ack,
    parse_ack,
    parse_datagram,
)

Direction = Literal["c2s", "s2c"]

# IPv6 (40) + UDP (8) header bytes: the worst case on the paths the matrix models.
IPV6_UDP_OVERHEAD = 48
_MAX_UDP = 65535
_JOIN_TIMEOUT = 5.0


@dataclass(frozen=True)
class Datagram:
    """One trace entry, appended when the datagram's fate is final.

    ``index`` is unique and follows arrival order; ``time`` is when it left or was dropped.
    A "replaced" datagram was not sent; the datagrams emitted for it carry its index as ``origin``.
    """

    index: int
    time: float  # seconds since proxy start
    direction: Literal["c2s", "s2c"]
    size: int
    payload: bytes
    action: Literal["forwarded", "dropped", "delayed", "replaced"]
    reason: str | None
    origin: int | None = None  # index of the replaced datagram this one was emitted for


@dataclass(frozen=True)
class Packet:
    """A received or rule-emitted datagram as rules see it."""

    index: int
    received: float  # seconds since proxy start
    direction: Direction
    payload: bytes
    parsed: ParsedDatagram
    origin: int | None = None


@dataclass(frozen=True)
class Verdict:
    action: Literal["forward", "drop", "hold", "replace"]
    reason: str | None = None
    payloads: tuple[bytes, ...] = ()  # "replace" only


FORWARD = Verdict("forward")


def drop(reason: str) -> Verdict:
    return Verdict("drop", reason)


def hold(reason: str) -> Verdict:
    """The rule keeps the packet and hands it back later from ``release``."""
    return Verdict("hold", reason)


def replace_with(reason: str, payloads: Sequence[bytes]) -> Verdict:
    """Send ``payloads`` as separate datagrams instead of the packet, through the later rules."""
    return Verdict("replace", reason, tuple(payloads))


class Rule:
    """Base for impairment rules; rules are stateful, so use a fresh instance per proxy.

    Rules run in list order; a packet released or emitted by rule i continues at rule i + 1.
    """

    def on_packet(self, packet: Packet, now: float) -> Verdict:
        raise NotImplementedError

    def deadline(self) -> float | None:
        """Proxy time at which ``release`` must be called next, or None."""
        return None

    def release(self, now: float) -> list[Packet]:
        """Held packets to send on now, in the order they should go out."""
        return []


PacketPredicate = Callable[[Packet], bool]


def ch1_fragments(packet: Packet) -> list[HandshakeFragment]:
    """Fragments of the initial ClientHello (message_seq 0) in a client-to-server packet."""
    if packet.direction != "c2s":
        return []
    return [
        f
        for f in packet.parsed.handshake_fragments()
        if f.msg_type == HS_CLIENT_HELLO and f.message_seq == 0
    ]


def ch1_fragment_at(offset: int) -> PacketPredicate:
    """Matches packets carrying the CH1 fragment that starts at ``offset``."""
    return lambda p: any(f.fragment_offset == offset for f in ch1_fragments(p))


class DropOnce(Rule):
    """Drop the first packet matching ``predicate``; forward everything else."""

    def __init__(self, predicate: PacketPredicate, reason: str = "drop once") -> None:
        self._predicate = predicate
        self._reason = reason
        self._done = False

    def on_packet(self, packet: Packet, now: float) -> Verdict:
        if not self._done and self._predicate(packet):
            self._done = True
            return drop(self._reason)
        return FORWARD


class ReorderClientHelloFragments(Rule):
    """Hold the datagrams carrying CH1 fragments, then release them in reverse order.

    Release happens once CH1 is fully covered or ``timeout`` after the first hold; acts once only.
    """

    reason = "reorder CH1 fragments"

    def __init__(self, timeout: float = 0.2) -> None:
        self._timeout = timeout
        self._held: list[Packet] = []
        self._fragments: list[HandshakeFragment] = []
        self._deadline: float | None = None
        self._done = False

    def on_packet(self, packet: Packet, now: float) -> Verdict:
        frags = ch1_fragments(packet)
        if self._done or not frags:
            return FORWARD
        self._fragments.extend(frags)
        if not self._held and covered(frags, frags[0].length):
            self._done = True  # CH1 fits in one datagram: nothing to reorder
            return FORWARD
        self._held.append(packet)
        if self._deadline is None:
            self._deadline = now + self._timeout
        if covered(self._fragments, frags[0].length):
            self._deadline = now
        return hold(self.reason)

    def deadline(self) -> float | None:
        return self._deadline

    def release(self, now: float) -> list[Packet]:
        if self._deadline is None or now < self._deadline:
            return []
        self._done = True
        self._deadline = None
        out, self._held = self._held[::-1], []
        return out


class SplitClientHello(Rule):
    """Send each unfragmented CH1 as ``fragments`` near-equal fragments, one record per datagram.

    Tests a server's CH1 reassembly with clients that never fragment CH1 (wolfSSL).
    List it before rules that should act on the fragments, e.g. ReorderClientHelloFragments.
    """

    def __init__(self, fragments: int = 2) -> None:
        if fragments < 2:
            raise ValueError("fragments must be at least 2")
        self._k = fragments
        self._split: set[int] = set()  # client epoch 0 sequence numbers that were split

    def on_packet(self, packet: Packet, now: float) -> Verdict:
        if packet.parsed.error is not None:
            return FORWARD
        if packet.direction == "c2s":
            return self._client_datagram(packet)
        return self._server_datagram(packet)

    def _client_datagram(self, packet: Packet) -> Verdict:
        out: list[bytes] = []
        cur = b""
        renumbered = split = False
        for rec in packet.parsed.records:
            if not isinstance(rec, PlaintextRecord) or rec.epoch != 0:
                cur += rec.to_bytes()
                continue
            # Client epoch 0 seq n becomes k*n + i: unique and in client order, so the server's
            # anti-replay window (RFC 9147 sec 4.5.1) sees no duplicate or stale number.
            base = rec.sequence_number * self._k
            if base + self._k - 1 > MAX_SEQUENCE_NUMBER:
                return FORWARD
            pieces = self._pieces(rec)
            if pieces is None:
                renumbered |= base != rec.sequence_number
                cur += replace(rec, sequence_number=base).to_bytes()
                continue
            split = True
            self._split.add(rec.sequence_number)
            if cur:
                out.append(cur)
                cur = b""
            for i, frag in enumerate(pieces):
                out.append(replace(rec, sequence_number=base + i, fragment=frag).to_bytes())
        if cur:
            out.append(cur)
        if split:
            return replace_with(f"split CH1 into {self._k} fragments", out)
        if renumbered:
            return replace_with("renumber client epoch 0 records", out)
        return FORWARD

    def _pieces(self, rec: PlaintextRecord) -> list[bytes] | None:
        if rec.content_type != CONTENT_HANDSHAKE or len(rec.handshake) != 1:
            return None
        ch = rec.handshake[0]
        if ch.msg_type != HS_CLIENT_HELLO or ch.message_seq != 0 or not ch.is_whole_message:
            return None
        if len(ch.body) != ch.length or ch.length < self._k:
            return None
        cuts = [ch.length * i // self._k for i in range(self._k + 1)]
        return [
            replace(ch, fragment_offset=a, fragment_length=b - a, body=ch.body[a:b]).to_bytes()
            for a, b in itertools.pairwise(cuts)
        ]

    def _server_datagram(self, packet: Packet) -> Verdict:
        records = [self._map_ack(r) for r in packet.parsed.records]
        if records == list(packet.parsed.records):
            return FORWARD
        return replace_with(
            "map ACK record numbers back", [b"".join(r.to_bytes() for r in records)]
        )

    def _map_ack(self, rec: Record) -> Record:
        # Plaintext ACKs name the renumbered records; map them back so the client's
        # retransmission logic (RFC 9147 sec 7.2) sees its own record numbers.
        if not isinstance(rec, PlaintextRecord) or rec.content_type != CONTENT_ACK:
            return rec
        numbers = parse_ack(rec.fragment)
        if numbers is None:
            return rec
        mapped = self._client_numbers(numbers)
        return rec if mapped == numbers else replace(rec, fragment=encode_ack(mapped))

    def _client_numbers(self, numbers: tuple[RecordNumber, ...]) -> tuple[RecordNumber, ...]:
        seen = {seq for epoch, seq in numbers if epoch == 0}
        acked = set()
        for seq in seen:
            n, i = divmod(seq, self._k)
            if n in self._split:
                # The client's record counts as received only once every piece of it is.
                if all(n * self._k + j in seen for j in range(self._k)):
                    acked.add(n)
            elif i == 0:
                acked.add(n)
        rest = [(epoch, seq) for epoch, seq in numbers if epoch != 0]
        return tuple(sorted([(0, n) for n in acked] + rest))


@dataclass
class _Held:
    packet: Packet
    rule: int
    reason: str | None


@dataclass
class _State:
    client: tuple[str, int] | None = None
    next_index: int = 0
    held: dict[int, _Held] = field(default_factory=dict)


class UdpProxy:
    """Forward datagrams between one client and ``server``; use as a context manager."""

    def __init__(
        self,
        server: tuple[str, int],
        *,
        pmtu: int | None = 1500,
        rules: Sequence[Rule] = (),
        cid_length: int = 0,
    ) -> None:
        self._server = server
        self._max_payload = None if pmtu is None else pmtu - IPV6_UDP_OVERHEAD
        self._rules = list(rules)
        self._cid_length = cid_length
        self._trace: list[Datagram] = []
        self._cond = threading.Condition()
        self._state = _State()
        self._sockets: list[socket.socket] = []
        self._thread: threading.Thread | None = None
        self._error: BaseException | None = None
        self._start = 0.0

    @property
    def address(self) -> tuple[str, int]:
        """Where the client sends to."""
        host, port = self._downstream.getsockname()[:2]
        return host, port

    @property
    def max_payload(self) -> int | None:
        return self._max_payload

    @property
    def trace(self) -> list[Datagram]:
        with self._cond:
            return list(self._trace)

    def wait_for(self, predicate: Callable[[list[Datagram]], bool], timeout: float) -> bool:
        """Block until ``predicate(trace)`` holds or ``timeout`` passes; returns the outcome."""
        with self._cond:
            return self._cond.wait_for(lambda: predicate(self._trace), timeout)

    def __enter__(self) -> UdpProxy:
        try:
            self._downstream = self._socket(socket.AF_INET)
            self._downstream.bind(("127.0.0.1", 0))
            family = socket.AF_INET6 if ":" in self._server[0] else socket.AF_INET
            self._upstream = self._socket(family)
            self._upstream.connect(self._server)
            self._wake_r, self._wake_w = socket.socketpair()
            self._sockets += [self._wake_r, self._wake_w]
            for s in self._sockets:
                s.setblocking(False)
            self._start = time.monotonic()
            self._thread = threading.Thread(target=self._run, name="udp-proxy", daemon=True)
            self._thread.start()
        except BaseException:
            self._close_sockets()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._thread is not None:
            self._wake_w.send(b"x")
            self._thread.join(_JOIN_TIMEOUT)
            if self._thread.is_alive():
                raise RuntimeError("UDP proxy thread did not stop")
        self._close_sockets()
        now = self._now()
        for _, h in sorted(self._state.held.items()):
            self._record(h.packet, now, "dropped", f"{h.reason}; held at exit")
        self._state.held.clear()
        if self._error is not None and exc_info[0] is None:
            raise RuntimeError("UDP proxy thread failed") from self._error

    def _socket(self, family: socket.AddressFamily) -> socket.socket:
        s = socket.socket(family, socket.SOCK_DGRAM)
        self._sockets.append(s)
        return s

    def _close_sockets(self) -> None:
        for s in self._sockets:
            s.close()
        self._sockets.clear()

    def _now(self) -> float:
        return time.monotonic() - self._start

    def _record(
        self,
        packet: Packet,
        now: float,
        action: Literal["forwarded", "dropped", "delayed", "replaced"],
        reason: str | None,
    ) -> None:
        entry = Datagram(
            packet.index,
            now,
            packet.direction,
            len(packet.payload),
            packet.payload,
            action,
            reason,
            packet.origin,
        )
        with self._cond:
            self._trace.append(entry)
            self._cond.notify_all()

    def _run(self) -> None:
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._downstream, selectors.EVENT_READ, "c2s")
            sel.register(self._upstream, selectors.EVENT_READ, "s2c")
            sel.register(self._wake_r, selectors.EVENT_READ, None)
            while True:
                for key, _ in sel.select(self._select_timeout()):
                    if key.data is None:
                        return
                    self._drain(key.fileobj, key.data)
                self._release_due()
        except BaseException as exc:
            self._error = exc
        finally:
            sel.close()

    def _select_timeout(self) -> float | None:
        deadlines = [d for r in self._rules if (d := r.deadline()) is not None]
        if not deadlines:
            return None
        return max(0.0, min(deadlines) - self._now())

    def _drain(self, sock: socket.socket, direction: Direction) -> None:
        while True:
            try:
                payload, addr = sock.recvfrom(_MAX_UDP)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                continue  # e.g. ICMP port unreachable from a server that is not up yet
            self._receive(payload, addr, direction)
            self._release_due()  # a hold may end with this datagram; release before the next one

    def _receive(self, payload: bytes, addr: tuple[str, int], direction: Direction) -> None:
        state = self._state
        packet = self._packet(payload, direction, origin=None)
        if direction == "c2s":
            if state.client is None:
                state.client = addr
            elif addr != state.client:
                self._record(packet, packet.received, "dropped", "unexpected source")
                return
        elif state.client is None:
            self._record(packet, packet.received, "dropped", "no client yet")
            return
        self._apply(packet, 0, None)

    def _packet(self, payload: bytes, direction: Direction, origin: int | None) -> Packet:
        index = self._state.next_index
        self._state.next_index += 1
        parsed = parse_datagram(payload, cid_length=self._cid_length)
        return Packet(index, self._now(), direction, payload, parsed, origin)

    def _apply(self, packet: Packet, first_rule: int, held_reason: str | None) -> None:
        now = self._now()
        for i in range(first_rule, len(self._rules)):
            verdict = self._rules[i].on_packet(packet, now)
            if verdict.action == "drop":
                self._record(packet, now, "dropped", verdict.reason)
                return
            if verdict.action == "hold":
                self._state.held[packet.index] = _Held(packet, i, verdict.reason)
                return
            if verdict.action == "replace":
                self._record(packet, now, "replaced", verdict.reason)
                for payload in verdict.payloads:
                    emitted = self._packet(payload, packet.direction, origin=packet.index)
                    self._apply(emitted, i + 1, None)
                return
        self._send(packet, held_reason)

    def _release_due(self) -> None:
        now = self._now()
        for rule in self._rules:
            d = rule.deadline()
            if d is None or d > now:
                continue
            for packet in rule.release(now):
                h = self._state.held.pop(packet.index)
                self._apply(packet, h.rule + 1, h.reason)

    def _send(self, packet: Packet, held_reason: str | None) -> None:
        now = self._now()
        # Checked after the rules: rules act at the sender, the PMTU is the path behind them.
        if self._max_payload is not None and len(packet.payload) > self._max_payload:
            self._record(packet, now, "dropped", "exceeds pmtu")
            return
        action: Literal["forwarded", "delayed"] = "forwarded"
        reason = None
        if held_reason is not None:
            action = "delayed"
            reason = f"{held_reason}; held {1000 * (now - packet.received):.1f} ms"
        try:
            if packet.direction == "c2s":
                self._upstream.send(packet.payload)
            elif self._state.client is not None:
                self._downstream.sendto(packet.payload, self._state.client)
        except OSError as exc:
            self._record(packet, now, "dropped", f"send: {exc}")
            return
        self._record(packet, now, action, reason)
