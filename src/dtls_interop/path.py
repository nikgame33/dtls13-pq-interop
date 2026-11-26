"""The runner's default network path: the UDP proxy configured from a scenario's PathConditions."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from dtls_interop.proxy import (
    Datagram,
    DropOnce,
    ReorderClientHelloFragments,
    Rule,
    SplitClientHello,
    UdpProxy,
    ch1_fragment_at,
)
from dtls_interop.records import HS_CLIENT_HELLO, HandshakeFragment, covered, parse_datagram
from dtls_interop.scenarios import Impairment, PathConditions

DROP_FIRST_CH1_FRAGMENT = "drop first CH1 fragment"
_HELD_FOR = re.compile(r"; held [0-9.]+ ms$")


def rules(conditions: PathConditions) -> list[Rule]:
    """Proxy rules in order; the split comes first so impairments act on its fragments."""
    out: list[Rule] = []
    if conditions.split_ch1 is not None:
        out.append(SplitClientHello(conditions.split_ch1))
    for impairment in conditions.impairments:
        if impairment is Impairment.REORDER_CH1:
            out.append(ReorderClientHelloFragments())
        elif impairment is Impairment.DROP_FIRST_CH1_FRAGMENT:
            out.append(DropOnce(ch1_fragment_at(0), DROP_FIRST_CH1_FRAGMENT))
        else:
            raise ValueError(f"unknown impairment {impairment!r}")
    return out


def proxy_path(server: tuple[str, int], conditions: PathConditions) -> UdpProxy:
    """A PathFactory for the runner."""
    return UdpProxy(server, pmtu=conditions.pmtu, rules=rules(conditions))


@dataclass(frozen=True)
class ClientHelloSummary:
    """A ClientHello as the client sent it, before any proxy rule."""

    size: int  # message length from the handshake header, without the 12-byte header itself
    fragments: int  # fragments in the client's first transmission


@dataclass(frozen=True)
class TraceSummary:
    ch1: ClientHelloSummary | None
    ch2: ClientHelloSummary | None
    # "action: reason" -> count for every datagram the proxy did not simply forward.
    actions: dict[str, int]


def summarize(trace: Sequence[object]) -> TraceSummary:
    """CH1/CH2 as sent by the client and what the proxy did; ignores non-proxy trace entries."""
    entries = [d for d in trace if isinstance(d, Datagram)]
    # Datagrams the proxy emitted for a replaced one have an origin; the client sent the rest.
    sent = [d for d in entries if d.direction == "c2s" and d.origin is None]
    # With --resume=ticket each connection is a flow; like the result lines, describe the last.
    last = max((d.flow for d in sent), default=0)
    sent = [d for d in sent if d.flow == last]
    hellos = [
        f
        for d in sent
        for f in parse_datagram(d.payload).handshake_fragments()
        if f.msg_type == HS_CLIENT_HELLO
    ]
    actions = Counter(
        f"{d.action}: {_HELD_FOR.sub('', d.reason or '')}"
        for d in entries
        if d.action != "forwarded"
    )
    return TraceSummary(
        ch1=_first_transmission(f for f in hellos if f.message_seq == 0),
        ch2=_first_transmission(f for f in hellos if f.message_seq == 1),
        actions=dict(sorted(actions.items())),
    )


def _first_transmission(fragments: Iterable[HandshakeFragment]) -> ClientHelloSummary | None:
    """Distinct fragments in sending order up to the first point where they cover the message."""
    seen: list[HandshakeFragment] = []
    spans: set[tuple[int, int]] = set()
    for frag in fragments:
        span = (frag.fragment_offset, frag.fragment_length)
        if span in spans:
            continue
        spans.add(span)
        seen.append(frag)
        if covered(seen, frag.length):
            break
    if not seen:
        return None
    return ClientHelloSummary(size=seen[0].length, fragments=len(seen))
