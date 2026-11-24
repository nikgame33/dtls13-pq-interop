"""Teardown order (docs/shim-interface.md, Lifecycle and teardown; ADR 0002)."""

from __future__ import annotations

from .harness import (
    TEARDOWN_WAIT,
    X25519,
    DropAlerts,
    Event,
    Harness,
    Pair,
    PairCase,
    Subject,
    check_pair_ok,
    teardown_events,
)

# Scheduling slack around the 2 s close_notify wait.
EARLY, LATE = 0.5, 3.0


def _events(p: Pair) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = {"ping": [], "pong": [], "client alert": [], "server alert": []}
    for e in teardown_events(p.trace):
        side = "client" if e.direction == "c2s" else "server"
        name = ("ping" if side == "client" else "pong") if e.kind == "app" else f"{side} alert"
        out[name].append(e)
    return out


def _ok(p: Pair) -> None:
    check_pair_ok(p, X25519, hrr=False, hrr_group=False)


def test_close_notify_order(pair: PairCase, harness: Harness) -> None:
    """ping, pong, the client's close_notify, then the server's."""
    p = harness.pair(pair)
    _ok(p)
    ev = _events(p)
    assert all(len(v) == 1 for v in ev.values()), ev
    order = [ev[k][0].index for k in ("ping", "pong", "client alert", "server alert")]
    assert order == sorted(order), ev


def test_server_waits_for_client_close_notify(server_subject: Subject, harness: Harness) -> None:
    """Without the client's close_notify the server waits 2 s, then still succeeds."""
    rule = DropAlerts("c2s")
    p = harness.pair(PairCase(server_subject.peer, server_subject.impl), rules=[rule])
    _ok(p)
    assert rule.dropped == 1
    ev = _events(p)
    pong, alert = ev["pong"][0].time, ev["server alert"][0].time
    assert TEARDOWN_WAIT - EARLY <= alert - pong <= TEARDOWN_WAIT + LATE, ev
    assert p.server.exited_at is not None
    assert p.server.exited_at - p.t0 - pong <= TEARDOWN_WAIT + LATE


def test_client_waits_for_server_close_notify(client_subject: Subject, harness: Harness) -> None:
    """Without the server's close_notify the client waits 2 s, then still succeeds."""
    rule = DropAlerts("s2c")
    p = harness.pair(PairCase(client_subject.impl, client_subject.peer), rules=[rule])
    _ok(p)
    assert rule.dropped == 1
    pong = _events(p)["pong"][0].time
    assert p.client is not None and p.client.exited_at is not None
    waited = p.client.exited_at - p.t0 - pong
    assert TEARDOWN_WAIT - EARLY <= waited <= TEARDOWN_WAIT + LATE, waited
