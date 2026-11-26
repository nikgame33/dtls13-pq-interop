"""Transport and Resumption (docs/shim-interface.md), checked on the wire through the proxies."""

from __future__ import annotations

import pytest

from dtls_interop.implementations import KNOWN_TRANSPORTS

from .harness import (
    EXIT_UNSUPPORTED,
    RUN_TIMEOUT,
    X25519,
    Harness,
    PairCase,
    Subject,
    check_hrr_per_flow,
    check_ok,
    check_protocol,
    unsupported,
)


def _declared(case: PairCase, transport: str) -> None:
    for impl in (case.client, case.server):
        if transport not in impl.transports:
            pytest.skip(f"{impl.id} does not declare {transport}")


def _options(transport: str, **extra: str) -> dict[str, str]:
    mtu = "default" if transport == "tls" else "1500"
    return {"transport": transport, "mtu": mtu, **extra}


def test_undeclared_transport_exits_2(subject: Subject, harness: Harness) -> None:
    """An adapter exits 2 for a transport its transports file does not list."""
    missing = sorted(KNOWN_TRANSPORTS - subject.impl.transports)
    if not missing:
        pytest.skip(f"{subject.impl.id} declares every transport")
    for transport in missing:
        opts = harness.options(subject.impl, subject.role, **_options(transport))
        run = harness.run(subject.impl, subject.role, [f"--{k}={v}" for k, v in opts], RUN_TIMEOUT)
        assert run.code == EXIT_UNSUPPORTED, run.describe()
        check_protocol(run)
        assert len(run.stdout) == 1, f"no ready line before exit 2\n{run.describe()}"


@pytest.mark.parametrize("validate", ["off", "cookie"])
def test_tls_handshake(pair: PairCase, harness: Harness, validate: str) -> None:
    """TLS 1.3 over TCP; a cookie HRR is answered by a CH2 that echoes the cookie."""
    _declared(pair, "tls")
    p = harness.pair(
        pair,
        client=_options("tls"),
        server=_options("tls", validate=validate),
    )
    cookie = validate == "cookie"
    flows = check_hrr_per_flow(p, True if cookie else None)
    assert len(flows) == 1, flows
    hrr = flows[0].hrr is not None
    for run in (p.client, p.server):
        check_ok(run, X25519, hrr=hrr, cookie=cookie, hrr_group=False, transport="tls")
    assert flows[0].cookie_echoed is (True if cookie else None), flows


@pytest.mark.parametrize("transport", sorted(KNOWN_TRANSPORTS))
def test_resumption(pair: PairCase, harness: Harness, transport: str) -> None:
    """Two connections from one process each; the second resumes the first.

    DTLS adds a cookie HRR to both (S10); over TLS that combination hits an OpenSSL bug
    (implementations/openssl/README.md), which is a library verdict, not a contract one.
    """
    _declared(pair, transport)
    cookie = transport == "dtls"
    try:
        p = harness.pair(
            pair,
            client=_options(transport, resume="ticket"),
            server=_options(transport, resume="ticket", validate="cookie" if cookie else "off"),
            client_may_be_unsupported=True,
        )
    except pytest.skip.Exception as e:
        assert "unsupported: connection 1: " in str(e), e
        raise
    if unsupported(p.client):
        check_protocol(p.client)
        assert p.client.result["error"].startswith("connection 1: "), p.client.describe()
        pytest.skip(f"client reports unsupported: {p.client.result['error']}")
    flows = check_hrr_per_flow(p, cookie)
    assert len(flows) == 2, flows
    for run in (p.client, p.server):
        check_ok(
            run,
            X25519,
            hrr=cookie,
            cookie=cookie,
            hrr_group=False,
            transport=transport,
            resumed=True,
        )
    assert all(f.cookie_echoed is (True if cookie else None) for f in flows), flows
