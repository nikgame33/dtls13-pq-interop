"""Groups, key share, validation and MTU (docs/shim-interface.md), checked on the wire."""

from __future__ import annotations

import pytest

from .harness import (
    EXIT_FAIL,
    GROUP_CODES,
    IP_UDP_OVERHEAD,
    MLKEM,
    P256,
    X25519,
    Harness,
    Pair,
    PairCase,
    Subject,
    check_pair_ok,
    check_protocol,
    datagram_sizes,
    unsupported,
)


def _skip_unsupported(p: Pair) -> None:
    for run in (p.client, p.server):
        if unsupported(run):
            check_protocol(run)
            pytest.skip(f"{run.role} reports unsupported: {run.result['error']}")


def _codes(*groups: str) -> tuple[int, ...]:
    return tuple(GROUP_CODES[g] for g in groups)


# (server --groups, client --groups, client --key-share, negotiated group, HRR expected)
SELECTION = {
    "rule1-share-beats-server-preference": (
        (MLKEM, X25519),
        (MLKEM, X25519),
        X25519,
        X25519,
        False,
    ),
    "rule1-pq-share": ((X25519, MLKEM), (X25519, MLKEM), MLKEM, MLKEM, False),
    "rule2-server-rank": ((MLKEM, X25519), (P256, X25519, MLKEM), P256, MLKEM, True),
    "rule2-server-rank-reversed": ((X25519, MLKEM), (P256, MLKEM, X25519), P256, X25519, True),
    "rule2-client-supported-only": ((MLKEM, X25519), (P256, X25519), P256, X25519, True),
}


@pytest.mark.parametrize("case", SELECTION.values(), ids=SELECTION.keys())
def test_server_group_selection(server_subject: Subject, harness: Harness, case) -> None:
    server_groups, client_groups, share, group, hrr = case
    p = harness.pair(
        PairCase(server_subject.peer, server_subject.impl),
        client={"groups": ",".join(client_groups), "key_share": share},
        server={"groups": ",".join(server_groups)},
    )
    _skip_unsupported(p)
    check_pair_ok(p, group, hrr=hrr, cookie=False, hrr_group=hrr)
    assert p.wire.client_hellos[0].key_shares[0].group == GROUP_CODES[share]
    if hrr:
        assert p.wire.hrr is not None and p.wire.hrr.selected_group == GROUP_CODES[group]


def test_no_mutual_group_fails(server_subject: Subject, harness: Harness) -> None:
    """Rule 3: no HRR, both sides fail."""
    p = harness.pair(
        PairCase(server_subject.peer, server_subject.impl),
        client={"groups": X25519, "key_share": X25519},
        server={"groups": MLKEM},
    )
    _skip_unsupported(p)
    for run in (p.client, p.server):
        assert run is not None and run.code == EXIT_FAIL, run and run.describe()
        check_protocol(run)
    assert p.wire.hrr is None and p.wire.group is None, p.wire


@pytest.mark.parametrize(
    "groups,share,mtu",
    [
        ((MLKEM, X25519), X25519, "1500"),
        ((X25519, MLKEM), MLKEM, "1500"),
        ((MLKEM,), MLKEM, "1280"),
    ],
    ids=["x25519", "pq", "pq-fragmented-ch1"],
)
def test_client_sends_exactly_the_requested_share(
    client_subject: Subject, harness: Harness, groups, share: str, mtu: str
) -> None:
    """--key-share=GROUP: exactly that share in CH1, or exit 2 before anything is sent."""
    p = harness.pair(
        PairCase(client_subject.impl, client_subject.peer),
        client={"groups": ",".join(groups), "key_share": share, "mtu": mtu},
        server={"groups": ",".join(groups), "mtu": mtu},
    )
    if unsupported(p.client):
        check_protocol(p.client)
        assert p.trace == [], "a client that cannot send the share must not send another CH1"
        pytest.skip(f"client reports unsupported: {p.client.result['error']}")
    check_pair_ok(p, share, hrr=False, cookie=False, hrr_group=False)
    assert [s.group for s in p.wire.client_hellos[0].key_shares] == [GROUP_CODES[share]]


def test_client_empty_key_share(client_subject: Subject, harness: Harness) -> None:
    """--key-share=empty: a key_share without entries, so the server must send an HRR."""
    p = harness.pair(
        PairCase(client_subject.impl, client_subject.peer),
        client={"groups": f"{X25519},{MLKEM}", "key_share": "empty"},
        server={"groups": f"{MLKEM},{X25519}"},
    )
    if unsupported(p.client):
        check_protocol(p.client)
        assert p.trace == [], "a client that cannot send an empty key_share must not send CH1"
        pytest.skip(f"client reports unsupported: {p.client.result['error']}")
    check_pair_ok(p, MLKEM, hrr=True, cookie=False, hrr_group=True)
    assert p.wire.client_hellos[0].key_shares == ()


def test_client_default_key_share(client_subject: Subject, harness: Harness) -> None:
    p = harness.pair(
        PairCase(client_subject.impl, client_subject.peer),
        client={"groups": f"{X25519},{MLKEM}", "key_share": "default"},
        server={"groups": f"{X25519},{MLKEM}"},
    )
    for run in (p.client, p.server):
        check_protocol(run)
        assert run is not None and run.result["ok"], run and run.describe()
    shares = {s.group for s in p.wire.client_hellos[0].key_shares}
    assert shares <= set(_codes(X25519, MLKEM)), p.wire


def test_client_supported_groups_in_order(client_subject: Subject, harness: Harness) -> None:
    groups = (P256, MLKEM, X25519)
    p = harness.pair(
        PairCase(client_subject.impl, client_subject.peer),
        client={"groups": ",".join(groups), "key_share": X25519},
        server={"groups": X25519},
    )
    _skip_unsupported(p)
    check_pair_ok(p, X25519, hrr=False, cookie=False, hrr_group=False)
    assert p.wire.client_hellos[0].supported_groups == _codes(*groups), p.wire


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_server_address_validation(server_subject: Subject, harness: Harness, validate) -> None:
    """--validate=cookie: an HRR with a cookie (and no selected_group) for a new peer."""
    p = harness.pair(
        PairCase(server_subject.peer, server_subject.impl), server={"validate": validate}
    )
    cookie = validate == "cookie"
    check_pair_ok(p, X25519, hrr=cookie, cookie=cookie, hrr_group=False)
    if cookie:
        assert len(p.wire.client_hellos) == 2 and p.wire.client_hellos[1].cookie, p.wire


@pytest.mark.parametrize("validate", ["off", "cookie"])
@pytest.mark.parametrize("mtu", [576, 1280, 1500])
def test_mtu_bounds_udp_payload(pair: PairCase, harness: Harness, mtu: int, validate) -> None:
    """--mtu=N: no datagram above N - 48 in either direction (the proxy does not enforce it)."""
    opts = {"groups": MLKEM, "mtu": str(mtu)}
    p = harness.pair(
        pair, client=opts | {"key_share": "default"}, server=opts | {"validate": validate}
    )
    _skip_unsupported(p)
    for run in (p.client, p.server):
        check_protocol(run)
        assert run is not None and run.result["ok"], run and run.describe()
    limit = mtu - IP_UDP_OVERHEAD
    for direction in ("c2s", "s2c"):
        sizes = datagram_sizes(p.trace, direction)
        assert sizes and max(sizes) <= limit, f"{direction}: {sizes}, limit {limit}"
