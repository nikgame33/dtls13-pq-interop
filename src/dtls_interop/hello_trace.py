"""What the ClientHellos and HelloRetryRequests in a proxy trace show (ADR 0004).

Reads what each endpoint sent, before any proxy rule acted on it, per flow (one client
connection), for UDP traces of DTLS and TCP traces of TLS.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from dtls_interop.proxy import Datagram
from dtls_interop.records import (
    HS_CLIENT_HELLO,
    HS_SERVER_HELLO,
    HandshakeFragment,
    HelloInfo,
    parse_datagram,
    parse_hello,
    parse_tls_handshake,
    reassemble,
)
from dtls_interop.tcp_proxy import Segment


@dataclass(frozen=True)
class FlowHellos:
    flow: int
    client_hellos: tuple[HelloInfo, ...]  # complete ClientHellos in the order the client sent them
    hrr: HelloInfo | None  # the server's HelloRetryRequest, if it sent one

    @property
    def cookie_echoed(self) -> bool | None:
        """Whether CH2 carries the HRR's cookie unchanged; None without a cookie HRR and a CH2."""
        if self.hrr is None or self.hrr.cookie_data is None or len(self.client_hellos) < 2:
            return None
        return self.client_hellos[1].cookie_data == self.hrr.cookie_data


def dtls_flows(trace: Sequence[Datagram]) -> list[FlowHellos]:
    sent: dict[int, dict[str, list[HandshakeFragment]]] = {}
    for d in trace:
        if d.origin is not None:
            continue  # emitted by a rule; the original datagram is in the trace too
        frags = sent.setdefault(d.flow, {"c2s": [], "s2c": []})[d.direction]
        frags += parse_datagram(d.payload).handshake_fragments()
    return [
        FlowHellos(flow, _dtls_client_hellos(f["c2s"]), _dtls_hrr(f["s2c"]))
        for flow, f in sorted(sent.items())
    ]


def _dtls_client_hellos(frags: list[HandshakeFragment]) -> tuple[HelloInfo, ...]:
    by_seq: dict[int, list[HandshakeFragment]] = {}
    for f in frags:
        if f.msg_type == HS_CLIENT_HELLO:
            by_seq.setdefault(f.message_seq, []).append(f)
    out = []
    for seq in sorted(by_seq):
        body = reassemble(_same_message(by_seq[seq]))
        hello = None if body is None else parse_hello(HS_CLIENT_HELLO, body)
        if hello is None:
            break  # a ClientHello the trace does not show completely ends the sequence
        out.append(hello)
    return tuple(out)


def _dtls_hrr(frags: list[HandshakeFragment]) -> HelloInfo | None:
    # The HRR is the server's first message (message_seq 0); a ServerHello there means no HRR.
    first = [f for f in frags if f.msg_type == HS_SERVER_HELLO and f.message_seq == 0]
    body = reassemble(_same_message(first))
    return None if body is None else parse_hello(HS_SERVER_HELLO, body)


def _same_message(frags: list[HandshakeFragment]) -> list[HandshakeFragment]:
    # A server that keeps no state may reuse message_seq 0 after its HRR; keep the first message.
    return [f for f in frags if f.length == frags[0].length] if frags else []


def tls_flows(trace: Sequence[Segment]) -> list[FlowHellos]:
    streams: dict[int, dict[str, bytes]] = {}
    for s in trace:
        per_flow = streams.setdefault(s.flow, {"c2s": b"", "s2c": b""})
        per_flow[s.direction] += s.payload
    out = []
    for flow, data in sorted(streams.items()):
        client = parse_tls_handshake(data["c2s"]).messages
        server = parse_tls_handshake(data["s2c"]).messages
        hellos = tuple(m.hello for m in client if m.msg_type == HS_CLIENT_HELLO and m.hello)
        hrr = server[0].hello if server and server[0].msg_type == HS_SERVER_HELLO else None
        out.append(FlowHellos(flow, hellos, hrr))
    return out


def cookie_echoed(flows: Sequence[FlowHellos]) -> bool | None:
    """False if any flow's CH2 failed to echo its HRR cookie, True if at least one echoed it."""
    seen = [f.cookie_echoed for f in flows if f.cookie_echoed is not None]
    if not seen:
        return None
    return all(seen)


def trace_flows(trace: Sequence[object]) -> list[FlowHellos] | None:
    """Analyse a UDP or TCP proxy trace; None for a trace of any other kind."""
    if all(isinstance(e, Datagram) for e in trace):
        return dtls_flows(trace)  # type: ignore[arg-type]
    if all(isinstance(e, Segment) for e in trace):
        return tls_flows(trace)  # type: ignore[arg-type]
    return None
