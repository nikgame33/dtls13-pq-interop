"""Best-effort parser for the DTLS records in one UDP datagram (RFC 9147 sec 4).

Built for traces: it never raises on malformed input and reports how far it got instead.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
CONTENT_HEARTBEAT = 24
CONTENT_ACK = 26
# tls12_cid (25) is absent: its header carries a CID whose length is not on the wire.
PLAINTEXT_CONTENT_TYPES = frozenset(
    {
        CONTENT_CHANGE_CIPHER_SPEC,
        CONTENT_ALERT,
        CONTENT_HANDSHAKE,
        CONTENT_APPLICATION_DATA,
        CONTENT_HEARTBEAT,
        CONTENT_ACK,
    }
)

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2

EXT_SUPPORTED_GROUPS = 10
EXT_COOKIE = 44
EXT_KEY_SHARE = 51

# SHA-256("HelloRetryRequest"), the ServerHello.random that marks an HRR (RFC 9846 sec 4.2.3).
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

PLAINTEXT_HEADER_LEN = 13
HANDSHAKE_HEADER_LEN = 12


@dataclass(frozen=True)
class KeyShareEntry:
    group: int
    size: int  # declared key_exchange length, even if the bytes are cut off


@dataclass(frozen=True)
class HelloInfo:
    """Key exchange view of a ClientHello or HelloRetryRequest."""

    kind: Literal["client_hello", "hello_retry_request"]
    key_shares: tuple[KeyShareEntry, ...]  # ClientHello only
    selected_group: int | None  # HelloRetryRequest only
    cookie: bool
    supported_groups: tuple[int, ...]
    partial: bool  # the message body was cut off before the end of the extensions


@dataclass(frozen=True)
class HandshakeFragment:
    msg_type: int
    length: int
    message_seq: int
    fragment_offset: int
    fragment_length: int
    body: bytes  # shorter than fragment_length if the record was truncated
    hello: HelloInfo | None

    @property
    def end(self) -> int:
        return self.fragment_offset + self.fragment_length

    @property
    def is_whole_message(self) -> bool:
        return self.fragment_offset == 0 and self.fragment_length == self.length


@dataclass(frozen=True)
class PlaintextRecord:
    content_type: int
    epoch: int
    sequence_number: int
    length: int
    fragment: bytes  # shorter than length if the datagram was truncated
    handshake: tuple[HandshakeFragment, ...] = ()
    legacy_version: int = 0xFEFD


@dataclass(frozen=True)
class CiphertextRecord:
    """DTLS 1.3 unified header record; the payload is encrypted and reported as opaque."""

    header: int  # first byte, 001CSLEE
    epoch_bits: int  # low two bits of the epoch
    sequence_bits: int  # low 8 or 16 bits, encrypted on the wire (record number encryption)
    connection_id: bytes | None
    length: int  # payload length, from the header or up to the end of the datagram
    payload: bytes
    has_length: bool


Record = PlaintextRecord | CiphertextRecord


@dataclass(frozen=True)
class ParsedDatagram:
    records: tuple[Record, ...]
    error: str | None = None  # set when parsing stopped early or a record was truncated

    def handshake_fragments(self) -> list[HandshakeFragment]:
        return [f for r in self.records if isinstance(r, PlaintextRecord) for f in r.handshake]


def parse_datagram(data: bytes, *, cid_length: int = 0) -> ParsedDatagram:
    """Parse every record in a UDP payload; ``cid_length`` is the negotiated connection ID size."""
    records: list[Record] = []
    pos = 0
    try:
        while pos < len(data):
            first = data[pos]
            if first & 0xE0 == 0x20:
                record, pos, error = _parse_ciphertext(data, pos, cid_length)
            elif first in PLAINTEXT_CONTENT_TYPES:
                record, pos, error = _parse_plaintext(data, pos)
            else:
                return ParsedDatagram(
                    tuple(records), f"unknown record type 0x{first:02x} at offset {pos}"
                )
            if record is not None:
                records.append(record)
            if error is not None:
                return ParsedDatagram(tuple(records), error)
    except Exception as exc:  # a parser bug must not break the proxy or a trace report
        return ParsedDatagram(tuple(records), f"parser error at offset {pos}: {exc!r}")
    return ParsedDatagram(tuple(records))


def _parse_plaintext(data: bytes, pos: int) -> tuple[PlaintextRecord | None, int, str | None]:
    if len(data) - pos < PLAINTEXT_HEADER_LEN:
        return None, len(data), f"truncated plaintext header at offset {pos}"
    content_type = data[pos]
    version = int.from_bytes(data[pos + 1 : pos + 3])
    epoch = int.from_bytes(data[pos + 3 : pos + 5])
    seq = int.from_bytes(data[pos + 5 : pos + 11])
    length = int.from_bytes(data[pos + 11 : pos + 13])
    start = pos + PLAINTEXT_HEADER_LEN
    fragment = data[start : start + length]
    error = None
    if len(fragment) < length:
        error = f"plaintext record at offset {pos} truncated: {len(fragment)} of {length} bytes"
    handshake: tuple[HandshakeFragment, ...] = ()
    if content_type == CONTENT_HANDSHAKE:
        handshake, hs_error = _parse_handshake_fragments(fragment, truncated=error is not None)
        error = error or hs_error
    record = PlaintextRecord(
        content_type=content_type,
        epoch=epoch,
        sequence_number=seq,
        length=length,
        fragment=fragment,
        handshake=handshake,
        legacy_version=version,
    )
    return record, start + len(fragment), error


def _parse_ciphertext(
    data: bytes, pos: int, cid_length: int
) -> tuple[CiphertextRecord | None, int, str | None]:
    header = data[pos]
    has_cid = bool(header & 0x10)
    seq_len = 2 if header & 0x08 else 1
    has_length = bool(header & 0x04)
    cur = pos + 1
    cid = None
    if has_cid:
        if cid_length <= 0:
            return None, len(data), f"record at offset {pos} has a connection ID of unknown length"
        cid = data[cur : cur + cid_length]
        cur += cid_length
    fixed = cur + seq_len + (2 if has_length else 0)
    if fixed > len(data):
        return None, len(data), f"truncated unified header at offset {pos}"
    seq_bits = int.from_bytes(data[cur : cur + seq_len])
    cur += seq_len
    error = None
    if has_length:
        length = int.from_bytes(data[cur : cur + 2])
        cur += 2
        payload = data[cur : cur + length]
        if len(payload) < length:
            error = f"ciphertext record at offset {pos} truncated: {len(payload)} of {length} bytes"
    else:
        payload = data[cur:]
        length = len(payload)
    record = CiphertextRecord(
        header=header,
        epoch_bits=header & 0x03,
        sequence_bits=seq_bits,
        connection_id=cid,
        length=length,
        payload=payload,
        has_length=has_length,
    )
    return record, cur + len(payload), error


def _parse_handshake_fragments(
    data: bytes, *, truncated: bool
) -> tuple[tuple[HandshakeFragment, ...], str | None]:
    fragments: list[HandshakeFragment] = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < HANDSHAKE_HEADER_LEN:
            return tuple(fragments), f"truncated handshake header at record offset {pos}"
        msg_type = data[pos]
        length = int.from_bytes(data[pos + 1 : pos + 4])
        message_seq = int.from_bytes(data[pos + 4 : pos + 6])
        offset = int.from_bytes(data[pos + 6 : pos + 9])
        frag_len = int.from_bytes(data[pos + 9 : pos + 12])
        start = pos + HANDSHAKE_HEADER_LEN
        body = data[start : start + frag_len]
        hello = None
        if offset == 0 and msg_type in (HS_CLIENT_HELLO, HS_SERVER_HELLO):
            hello = parse_hello(msg_type, body, complete=len(body) == length)
        fragments.append(
            HandshakeFragment(msg_type, length, message_seq, offset, frag_len, body, hello)
        )
        if len(body) < frag_len:
            if truncated:
                return tuple(fragments), None  # already reported at the record level
            return tuple(fragments), f"handshake fragment at record offset {pos} overruns record"
        pos = start + frag_len
    return tuple(fragments), None


class _Truncated(Exception):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise _Truncated
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n))

    def vector(self, len_bytes: int) -> bytes:
        return self.take(self.uint(len_bytes))

    @property
    def remaining(self) -> bytes:
        return self.data[self.pos :]


def parse_hello(msg_type: int, body: bytes, *, complete: bool = True) -> HelloInfo | None:
    """Extract key exchange details from a ClientHello or HRR body starting at offset 0.

    Returns None for a ServerHello that is not an HRR. ``complete=False`` marks the result partial.
    """
    r = _Reader(body)
    try:
        r.take(2 + 32 if msg_type == HS_CLIENT_HELLO else 2)
        if msg_type == HS_SERVER_HELLO and r.take(32) != HRR_RANDOM:
            return None
    except _Truncated:
        if msg_type == HS_CLIENT_HELLO:
            return HelloInfo("client_hello", (), None, False, (), partial=True)
        return None

    kind: Literal["client_hello", "hello_retry_request"]
    kind = "client_hello" if msg_type == HS_CLIENT_HELLO else "hello_retry_request"
    key_shares: list[KeyShareEntry] = []
    selected: list[int] = []
    groups: list[int] = []
    cookie = False
    partial = not complete
    try:
        r.vector(1)  # legacy_session_id
        if kind == "client_hello":
            r.vector(1)  # legacy_cookie
            r.vector(2)  # cipher_suites
            r.vector(1)  # legacy_compression_methods
        else:
            r.take(3)  # cipher_suite, legacy_compression_method
        ext_total = r.uint(2)
        exts = _Reader(r.remaining[:ext_total])
        if len(exts.data) < ext_total:
            partial = True
        while exts.remaining:
            ext_type = exts.uint(2)
            ext_len = exts.uint(2)
            if ext_type == EXT_COOKIE:
                cookie = True
            ext = _Reader(exts.remaining[:ext_len])
            try:
                if ext_type == EXT_SUPPORTED_GROUPS:
                    _read_groups(ext, groups)
                elif ext_type == EXT_KEY_SHARE and kind == "client_hello":
                    _read_client_shares(ext, key_shares)
                elif ext_type == EXT_KEY_SHARE:
                    selected.append(ext.uint(2))
            finally:
                exts.take(ext_len)  # raises _Truncated after recording what was readable
    except _Truncated:
        partial = True
    return HelloInfo(
        kind=kind,
        key_shares=tuple(key_shares),
        selected_group=selected[0] if selected else None,
        cookie=cookie,
        supported_groups=tuple(groups),
        partial=partial,
    )


def _read_groups(ext: _Reader, out: list[int]) -> None:
    size = ext.uint(2)
    lst = _Reader(ext.remaining[:size])
    while len(lst.remaining) >= 2:
        out.append(lst.uint(2))


def _read_client_shares(ext: _Reader, out: list[KeyShareEntry]) -> None:
    total = ext.uint(2)
    shares = _Reader(ext.remaining[:total])
    while len(shares.remaining) >= 4:
        group = shares.uint(2)
        size = shares.uint(2)
        out.append(KeyShareEntry(group, size))
        shares.pos += size


def covered(fragments: Iterable[HandshakeFragment], length: int) -> bool:
    """True if the fragments together cover bytes [0, length) of one handshake message."""
    reached = 0
    for frag in sorted(fragments, key=lambda f: f.fragment_offset):
        if frag.fragment_offset > reached:
            return False
        reached = max(reached, frag.end)
    return reached >= length


def reassemble(fragments: Iterable[HandshakeFragment]) -> bytes | None:
    """Rebuild one handshake message body from its fragments, or None while bytes are missing."""
    frags = [f for f in fragments if len(f.body) == f.fragment_length]
    if not frags:
        return None
    length = frags[0].length
    if not covered(frags, length):
        return None
    buf = bytearray(length)
    for f in frags:
        buf[f.fragment_offset : f.end] = f.body
    return bytes(buf)
