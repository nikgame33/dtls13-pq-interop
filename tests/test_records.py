"""Record parser tests on byte vectors assembled field by field from RFC 9147 / RFC 9846."""

from __future__ import annotations

import random

import pytest

from dtls_interop.records import (
    HRR_RANDOM,
    CiphertextRecord,
    HelloInfo,
    KeyShareEntry,
    PlaintextRecord,
    covered,
    encode_ack,
    parse_ack,
    parse_datagram,
    parse_hello,
    reassemble,
)

X25519 = 0x001D
X25519MLKEM768 = 0x11EC
MLKEM512X25519 = 0x11EA
X25519MLKEM768_SHARE = 1216


def u8(v: int) -> bytes:
    return v.to_bytes(1)


def u16(v: int) -> bytes:
    return v.to_bytes(2)


def u24(v: int) -> bytes:
    return v.to_bytes(3)


def ext(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + u16(len(data)) + data


def supported_groups(*groups: int) -> bytes:
    body = b"".join(u16(g) for g in groups)
    return ext(10, u16(len(body)) + body)


def key_share(*shares: tuple[int, int]) -> bytes:
    body = b"".join(u16(g) + u16(n) + bytes([0xAB]) * n for g, n in shares)
    return ext(51, u16(len(body)) + body)


def client_hello(*extensions: bytes) -> bytes:
    exts = b"".join(extensions)
    return (
        u16(0xFEFD)  # legacy_version: DTLS 1.2
        + bytes(32)  # random
        + u8(0)  # legacy_session_id
        + u8(0)  # legacy_cookie
        + u16(2)
        + u16(0x1301)  # cipher_suites
        + u8(1)
        + u8(0)  # legacy_compression_methods
        + u16(len(exts))
        + exts
    )


def hello_retry_request(*extensions: bytes) -> bytes:
    exts = b"".join(extensions)
    return u16(0xFEFD) + HRR_RANDOM + u8(0) + u16(0x1301) + u8(0) + u16(len(exts)) + exts


def hs_fragment(msg_type: int, body: bytes, *, seq: int = 0, offset: int = 0, size: int = -1):
    """One handshake fragment carrying body[offset:offset+size]."""
    size = len(body) - offset if size < 0 else size
    part = body[offset : offset + size]
    return u8(msg_type) + u24(len(body)) + u16(seq) + u24(offset) + u24(len(part)) + part


def plaintext(content_type: int, fragment: bytes, *, epoch: int = 0, seq: int = 0) -> bytes:
    return (
        u8(content_type)
        + u16(0xFEFD)
        + u16(epoch)
        + seq.to_bytes(6)
        + u16(len(fragment))
        + (fragment)
    )


PQ_CH = client_hello(
    supported_groups(X25519MLKEM768, X25519),
    key_share((X25519MLKEM768, X25519MLKEM768_SHARE)),
)


def test_single_plaintext_handshake_record() -> None:
    parsed = parse_datagram(plaintext(22, hs_fragment(1, PQ_CH), seq=7))
    assert parsed.error is None
    (record,) = parsed.records
    assert isinstance(record, PlaintextRecord)
    assert (record.content_type, record.epoch, record.sequence_number) == (22, 0, 7)
    assert record.length == len(PQ_CH) + 12
    (frag,) = record.handshake
    assert (frag.msg_type, frag.message_seq, frag.fragment_offset) == (1, 0, 0)
    assert frag.is_whole_message
    assert frag.hello == HelloInfo(
        kind="client_hello",
        key_shares=(KeyShareEntry(X25519MLKEM768, X25519MLKEM768_SHARE),),
        selected_group=None,
        cookie=False,
        supported_groups=(X25519MLKEM768, X25519),
        partial=False,
    )


def test_client_hello_split_across_two_fragments() -> None:
    cut = 600  # inside the 1216-byte key share, as at a 1280-byte PMTU with a small MTU setting
    first = parse_datagram(plaintext(22, hs_fragment(1, PQ_CH, size=cut)))
    second = parse_datagram(plaintext(22, hs_fragment(1, PQ_CH, offset=cut), seq=1))
    assert first.error is None and second.error is None
    (f1,) = first.handshake_fragments()
    (f2,) = second.handshake_fragments()
    assert (f1.fragment_offset, f1.fragment_length, f1.length) == (0, cut, len(PQ_CH))
    assert (f2.fragment_offset, f2.end) == (cut, len(PQ_CH))
    assert f1.hello is not None and f1.hello.partial
    # The key share header is in the first fragment, so its group and declared size are known.
    assert f1.hello.key_shares == (KeyShareEntry(X25519MLKEM768, X25519MLKEM768_SHARE),)
    assert f1.hello.supported_groups == (X25519MLKEM768, X25519)
    assert f2.hello is None
    assert not covered([f1], len(PQ_CH))
    assert covered([f2, f1], len(PQ_CH))
    assert reassemble([f2, f1]) == PQ_CH
    full = parse_hello(1, reassemble([f1, f2]) or b"")
    assert full is not None and not full.partial


def test_fragment_cut_before_extensions_is_partial() -> None:
    parsed = parse_datagram(plaintext(22, hs_fragment(1, PQ_CH, size=20)))
    assert parsed.error is None
    (frag,) = parsed.handshake_fragments()
    assert frag.hello == HelloInfo("client_hello", (), None, False, (), partial=True)


def test_several_handshake_fragments_in_one_record() -> None:
    body = hs_fragment(1, PQ_CH, size=100) + hs_fragment(1, PQ_CH, offset=100, size=50)
    parsed = parse_datagram(plaintext(22, body))
    assert parsed.error is None
    offsets = [(f.fragment_offset, f.fragment_length) for f in parsed.handshake_fragments()]
    assert offsets == [(0, 100), (100, 50)]


def test_hello_retry_request_with_cookie() -> None:
    hrr = hello_retry_request(ext(43, u16(0xFEFC)), ext(51, u16(X25519MLKEM768)), ext(44, u16(3)))
    (frag,) = parse_datagram(plaintext(22, hs_fragment(2, hrr))).handshake_fragments()
    assert frag.hello == HelloInfo(
        kind="hello_retry_request",
        key_shares=(),
        selected_group=X25519MLKEM768,
        cookie=True,
        supported_groups=(),
        partial=False,
    )


def test_plain_server_hello_has_no_hello_info() -> None:
    sh = u16(0xFEFD) + bytes(32) + u8(0) + u16(0x1301) + u8(0) + u16(0)
    (frag,) = parse_datagram(plaintext(22, hs_fragment(2, sh))).handshake_fragments()
    assert frag.hello is None


def test_client_hello_with_empty_key_share_and_cookie() -> None:
    ch = client_hello(supported_groups(MLKEM512X25519), key_share(), ext(44, u16(2) + b"\x01\x02"))
    hello = parse_hello(1, ch)
    assert hello is not None
    assert (hello.key_shares, hello.cookie, hello.partial) == ((), True, False)


def test_unified_header_with_length() -> None:
    # 001 C=0 S=1 L=1 EE=11: epoch 3, 16-bit sequence, explicit length.
    record = bytes([0b0010_1111]) + u16(0x1234) + u16(5) + b"\x01" * 5
    parsed = parse_datagram(record)
    assert parsed.error is None
    (rec,) = parsed.records
    assert rec == CiphertextRecord(
        header=0x2F,
        epoch_bits=3,
        sequence_bits=0x1234,
        connection_id=None,
        length=5,
        payload=b"\x01" * 5,
        has_length=True,
    )


def test_unified_header_without_length_runs_to_end_of_datagram() -> None:
    # 001 C=0 S=0 L=0 EE=10: 8-bit sequence, no length field.
    record = bytes([0b0010_0010]) + u8(9) + b"\x02" * 40
    (rec,) = parse_datagram(record).records
    assert isinstance(rec, CiphertextRecord)
    assert (rec.epoch_bits, rec.sequence_bits, rec.length, rec.has_length) == (2, 9, 40, False)


def test_unified_header_connection_id() -> None:
    record = bytes([0b0011_0101]) + b"\xc1\xd2" + u8(1) + u16(3) + b"xyz"
    assert parse_datagram(record).error is not None  # CID length unknown
    (rec,) = parse_datagram(record, cid_length=2).records
    assert isinstance(rec, CiphertextRecord)
    assert (rec.connection_id, rec.payload) == (b"\xc1\xd2", b"xyz")


def test_coalesced_datagram() -> None:
    hrr = hello_retry_request(ext(51, u16(X25519MLKEM768)))
    ack = plaintext(26, u16(0), seq=1)
    encrypted = bytes([0b0010_1110]) + u16(1) + u16(4) + b"\x03" * 4
    tail = bytes([0b0010_0010]) + u8(0) + b"\x04" * 7
    parsed = parse_datagram(plaintext(22, hs_fragment(2, hrr)) + ack + encrypted + tail)
    assert parsed.error is None
    kinds = [(type(r).__name__, getattr(r, "content_type", None), r.length) for r in parsed.records]
    assert kinds == [
        ("PlaintextRecord", 22, len(hrr) + 12),
        ("PlaintextRecord", 26, 2),
        ("CiphertextRecord", None, 4),
        ("CiphertextRecord", None, 7),
    ]


def test_truncated_input_never_raises() -> None:
    first = plaintext(22, hs_fragment(1, PQ_CH))
    data = first + plaintext(21, b"\x02\x28")
    for cut in range(len(data)):
        parsed = parse_datagram(data[:cut])
        assert (parsed.error is None) == (cut in (0, len(first))), cut
        for frag in parsed.handshake_fragments():
            if frag.hello is not None and len(frag.body) < frag.length:
                assert frag.hello.partial, cut


def test_truncated_record_keeps_parsed_prefix() -> None:
    good = plaintext(21, b"\x02\x28")
    parsed = parse_datagram(good + plaintext(22, hs_fragment(1, PQ_CH))[:700])
    assert parsed.error is not None and "truncated" in parsed.error
    assert [r.length for r in parsed.records] == [2, len(PQ_CH) + 12]
    hello = parsed.handshake_fragments()[0].hello
    assert hello is not None and hello.partial
    assert hello.key_shares == (KeyShareEntry(X25519MLKEM768, X25519MLKEM768_SHARE),)


@pytest.mark.parametrize(
    "data",
    [
        b"\x00",
        b"\x16\xfe",
        b"\xff" * 20,
        b"\x30",  # unified header, CID bit, no CID length known
        b"\x2c\x01",  # unified header, L bit, length missing
        plaintext(22, b"\x01\x00\x00\x05\x00"),  # short handshake header
        plaintext(22, hs_fragment(1, PQ_CH)[:12] + b"\x00" * 5),  # fragment overruns record
    ],
)
def test_malformed_input_reports_error(data: bytes) -> None:
    assert parse_datagram(data).error is not None


def test_garbage_client_hello_body_is_partial() -> None:
    parsed = parse_datagram(plaintext(22, hs_fragment(1, b"\xff" * 60)))
    assert parsed.error is None
    (frag,) = parsed.handshake_fragments()
    assert frag.hello is not None and frag.hello.partial


def test_empty_datagram() -> None:
    assert parse_datagram(b"").records == ()
    assert parse_datagram(b"").error is None


def test_mutated_input_hits_no_parser_bug() -> None:
    # The top-level guard would hide a bug as "parser error"; mutated vectors must not reach it.
    rng = random.Random(1)
    base = plaintext(22, hs_fragment(1, PQ_CH, size=900)) + bytes([0x2E]) + u16(1) + u16(3) + b"abc"
    for _ in range(3000):
        data = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        parsed = parse_datagram(bytes(data[: rng.randint(0, len(data))]))
        assert parsed.error is None or not parsed.error.startswith("parser error"), parsed.error


def test_records_reencode_to_the_same_bytes() -> None:
    hrr = hello_retry_request(ext(51, u16(X25519MLKEM768)))
    data = (
        plaintext(22, hs_fragment(2, hrr) + hs_fragment(1, PQ_CH, offset=3, size=40), seq=5)
        + bytes([0b0011_1101]) + b"\xc1\xd2" + u16(0x0102) + u16(3) + b"xyz"
        + bytes([0b0010_0010]) + u8(9) + b"\x02" * 40
    )  # fmt: skip
    parsed = parse_datagram(data, cid_length=2)
    assert parsed.error is None
    assert b"".join(r.to_bytes() for r in parsed.records) == data
    handshake = parsed.records[0]
    assert isinstance(handshake, PlaintextRecord)
    assert b"".join(f.to_bytes() for f in handshake.handshake) == handshake.fragment


def test_ack_round_trip() -> None:
    numbers = ((0, 1), (0, 2), (2, 0x0102030405))
    body = encode_ack(numbers)
    assert body == u16(48) + b"".join(e.to_bytes(8) + s.to_bytes(8) for e, s in numbers)
    assert parse_ack(body) == numbers
    assert parse_ack(encode_ack([])) == ()
    assert parse_ack(body[:-1]) is None
    assert parse_ack(u16(15) + bytes(15)) is None
