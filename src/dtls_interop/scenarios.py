"""Scenario definitions from docs/test-matrix.md. Data only; the runner interprets them."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class Transport(StrEnum):
    DTLS = "dtls"
    TLS = "tls"


# Option value meaning "do not configure, let the library decide" (--mtu, --key-share).
DEFAULT = "default"
# `--key-share` value for an empty key_share extension.
EMPTY_KEY_SHARE = "empty"


class Validate(StrEnum):
    OFF = "off"
    COOKIE = "cookie"


class Impairment(StrEnum):
    """Path impairments by name; the runner's path factory maps them to proxy rules."""

    REORDER_CH1 = "reorder-ch1"
    DROP_FIRST_CH1_FRAGMENT = "drop-first-ch1-fragment"


@dataclass(frozen=True)
class ClientOptions:
    groups: tuple[str, ...]
    key_share: str  # a group, EMPTY_KEY_SHARE or DEFAULT
    mtu: int | str  # IP-layer path MTU or DEFAULT


@dataclass(frozen=True)
class ServerOptions:
    groups: tuple[str, ...]
    validate: Validate
    mtu: int | str


@dataclass(frozen=True)
class PathConditions:
    pmtu: int
    impairments: tuple[Impairment, ...] = ()
    # The proxy delivers an unfragmented CH1 as this many fragments (ADR 0003); None: off.
    split_ch1: int | None = None


@dataclass(frozen=True)
class Expected:
    """What a passing run looks like; None means "not checked"."""

    summary: str
    version: str | None = None
    group: str | None = None
    hrr: bool | None = None
    hrr_cookie: bool | None = None
    hrr_group: bool | None = None
    # Checked against the CH1/CH2 the client sent, as the proxy trace shows them.
    ch1_fragmented: bool | None = None
    ch2_fragmented: bool | None = None
    round_trips: int | None = None


@dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    client: ClientOptions
    server: ServerOptions
    path: PathConditions
    expected: Expected
    transport: Transport = Transport.DTLS
    # Two handshakes: the second resumes with the PSK from the first.
    resumption: bool = False


X25519 = "X25519"
X25519MLKEM768 = "X25519MLKEM768"
MLKEM512X25519 = "MLKEM512X25519"
SECP256R1MLKEM768 = "SecP256r1MLKEM768"

DTLS13 = "DTLSv1.3"
TLS13 = "TLSv1.3"


def _cookie_frag(sid: str, description: str, impairments: tuple[Impairment, ...]) -> Scenario:
    """S04 and its impaired variants S08, S09."""
    return Scenario(
        id=sid,
        description=description,
        client=ClientOptions(groups=(X25519MLKEM768,), key_share=X25519MLKEM768, mtu=1280),
        server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.COOKIE, mtu=1280),
        path=PathConditions(pmtu=1280, impairments=impairments),
        expected=Expected(
            summary="Succeeds",
            version=DTLS13,
            group=X25519MLKEM768,
            hrr=True,
            hrr_cookie=True,
            hrr_group=False,
            ch1_fragmented=True,
        ),
    )


# Every scenario pins --mtu to its path PMTU and --key-share to the share the row names, so a
# row means the same configuration for every library; DEFAULT is for library-default rows.
def _build() -> tuple[Scenario, ...]:
    return (
        Scenario(
            id="S01",
            description="X25519, full share, PMTU 1500, no validation",
            client=ClientOptions(groups=(X25519,), key_share=X25519, mtu=1500),
            server=ServerOptions(groups=(X25519,), validate=Validate.OFF, mtu=1500),
            path=PathConditions(pmtu=1500),
            expected=Expected(
                summary="Handshake succeeds, 1 RTT",
                version=DTLS13,
                group=X25519,
                hrr=False,
                hrr_cookie=False,
                hrr_group=False,
                ch1_fragmented=False,
                round_trips=1,
            ),
        ),
        Scenario(
            id="S02",
            description="X25519MLKEM768, full share, PMTU 1500",
            client=ClientOptions(groups=(X25519MLKEM768,), key_share=X25519MLKEM768, mtu=1500),
            server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.OFF, mtu=1500),
            path=PathConditions(pmtu=1500),
            expected=Expected(
                summary="Succeeds, CH1 in one datagram",
                version=DTLS13,
                group=X25519MLKEM768,
                hrr=False,
                hrr_cookie=False,
                hrr_group=False,
                ch1_fragmented=False,
            ),
        ),
        Scenario(
            id="S03",
            description="X25519MLKEM768, full share, PMTU 1280",
            client=ClientOptions(groups=(X25519MLKEM768,), key_share=X25519MLKEM768, mtu=1280),
            server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.OFF, mtu=1280),
            path=PathConditions(pmtu=1280),
            expected=Expected(
                summary="Succeeds with fragmented CH1",
                version=DTLS13,
                group=X25519MLKEM768,
                hrr=False,
                hrr_cookie=False,
                hrr_group=False,
                ch1_fragmented=True,
            ),
        ),
        _cookie_frag("S04", "S03 + server stateless HRR cookie", ()),
        Scenario(
            id="S05",
            description="Empty key_share + HRR (X25519MLKEM768)",
            client=ClientOptions(groups=(X25519MLKEM768,), key_share=EMPTY_KEY_SHARE, mtu=1500),
            server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.OFF, mtu=1500),
            path=PathConditions(pmtu=1500),
            # hrr_cookie unchecked: a server may add a cookie to any HRR.
            expected=Expected(
                summary="Succeeds, 2 RTT",
                version=DTLS13,
                group=X25519MLKEM768,
                hrr=True,
                hrr_group=True,
                round_trips=2,
            ),
        ),
        Scenario(
            id="S06",
            description="Wrong guess (X25519 share, server requires hybrid)",
            client=ClientOptions(groups=(X25519, X25519MLKEM768), key_share=X25519, mtu=1500),
            server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.OFF, mtu=1500),
            path=PathConditions(pmtu=1500),
            expected=Expected(
                summary="Succeeds via HRR",
                version=DTLS13,
                group=X25519MLKEM768,
                hrr=True,
                hrr_group=True,
            ),
        ),
        Scenario(
            id="S07",
            description="MLKEM512X25519, full share, PMTU 1280, cookie",
            client=ClientOptions(groups=(MLKEM512X25519,), key_share=MLKEM512X25519, mtu=1280),
            server=ServerOptions(groups=(MLKEM512X25519,), validate=Validate.COOKIE, mtu=1280),
            path=PathConditions(pmtu=1280),
            expected=Expected(
                summary="Succeeds, CH1 and CH2 unfragmented",
                version=DTLS13,
                group=MLKEM512X25519,
                hrr=True,
                hrr_cookie=True,
                hrr_group=False,
                ch1_fragmented=False,
                ch2_fragmented=False,
            ),
        ),
        _cookie_frag("S08", "S04 with CH1 fragments reordered", (Impairment.REORDER_CH1,)),
        _cookie_frag(
            "S09",
            "S04 with first CH1 fragment lost once",
            (Impairment.DROP_FIRST_CH1_FRAGMENT,),
        ),
        Scenario(
            id="S10",
            description="PSK resumption after HRR at PMTU 1280",
            client=ClientOptions(groups=(X25519MLKEM768,), key_share=X25519MLKEM768, mtu=1280),
            server=ServerOptions(groups=(X25519MLKEM768,), validate=Validate.COOKIE, mtu=1280),
            path=PathConditions(pmtu=1280),
            expected=Expected(
                summary="Succeeds",
                version=DTLS13,
                group=X25519MLKEM768,
                hrr=True,
                hrr_cookie=True,
                hrr_group=False,
            ),
            resumption=True,
        ),
        Scenario(
            id="T01",
            description="TLS 1.3 HRR cookie echo (incl. mbedtls)",
            client=ClientOptions(groups=(X25519,), key_share=X25519, mtu=1500),
            server=ServerOptions(groups=(X25519,), validate=Validate.COOKIE, mtu=1500),
            path=PathConditions(pmtu=1500),
            expected=Expected(
                summary="Cookie echoed in CH2",
                version=TLS13,
                group=X25519,
                hrr=True,
                hrr_cookie=True,
                hrr_group=False,
            ),
            transport=Transport.TLS,
        ),
    )


# Suffix of the rows that rerun a fragmented-CH1 scenario with CH1 split by the proxy.
SPLIT_SUFFIX = "+split"
SPLIT_FRAGMENTS = 2
# Lets a client that never fragments CH1 (wolfSSL) send its full share: CH1 must fit one datagram.
# The row's only MTU: path PMTU and both peers' --mtu.
SPLIT_MTU = 1500


def _split_row(base: Scenario) -> Scenario:
    """The base row with CH1 split by the proxy instead of by the client (ADR 0003)."""
    return replace(
        base,
        id=base.id + SPLIT_SUFFIX,
        description=f"{base.id}, MTU {SPLIT_MTU} on path and peers, proxy splits CH1 in two",
        client=replace(base.client, mtu=SPLIT_MTU),
        server=replace(base.server, mtu=SPLIT_MTU),
        path=replace(base.path, pmtu=SPLIT_MTU, split_ch1=SPLIT_FRAGMENTS),
        expected=replace(
            base.expected,
            summary=f"As {base.id}; CH1 reaches the server in {SPLIT_FRAGMENTS} fragments",
            ch1_fragmented=None,
        ),
    )


_BASE = _build()
SCENARIOS: tuple[Scenario, ...] = _BASE + tuple(
    _split_row(s) for s in _BASE if s.expected.ch1_fragmented
)
_BY_ID = {s.id.upper(): s for s in SCENARIOS}


def get(scenario_id: str) -> Scenario:
    try:
        return _BY_ID[scenario_id.upper()]
    except KeyError:
        known = ", ".join(_BY_ID)
        raise KeyError(f"unknown scenario {scenario_id!r} (known: {known})") from None
