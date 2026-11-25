"""Lifecycle, output protocol and exit codes (docs/shim-interface.md) for every entry."""

from __future__ import annotations

import json

import pytest

from dtls_interop import pki
from dtls_interop.implementations import CLIENT, SERVER

from .harness import (
    EXIT_FAIL,
    EXIT_OK,
    EXIT_UNSUPPORTED,
    X25519,
    Harness,
    PairCase,
    Subject,
    await_ready,
    check_pair_ok,
    check_protocol,
    free_port,
    port_is_bound,
    ready_port,
    render,
)

# Not a final IANA code point (draft-rosomakho-tls-ecdhe-mlkem512); few libraries have it.
RARE_GROUP = "MLKEM512X25519"
PROBE_TIMEOUT = 5.0


def _ready(harness: Harness, subject: Subject, port: str) -> tuple[str | None, bool]:
    """First stdout line of a server on --port=port, and whether that port is bound by then."""
    opts = harness.options(subject.impl, SERVER, port=port)
    adapter = harness.start(subject.impl, SERVER, render(opts, "equals"))
    bound = port_is_bound(await_ready(adapter))
    line = adapter.first_line(0)
    run = adapter.finish()
    assert run.code is None, f"the server must wait for a client after ready\n{run.describe()}"
    return line, bound


def test_ready_line_reports_bound_port(server_subject: Subject, harness: Harness) -> None:
    line, bound = _ready(harness, server_subject, "0")
    assert line is not None, "no ready line"
    event = json.loads(line)
    assert event.keys() == {"event", "port"} and event["event"] == "ready", line
    assert ready_port(line) is not None, line
    assert bound, f"port in {line} is not bound"


def test_ready_line_reports_requested_port(server_subject: Subject, harness: Harness) -> None:
    port = free_port()
    line, bound = _ready(harness, server_subject, str(port))
    assert ready_port(line) == port and bound, line


def test_successful_handshake_result_lines(pair: PairCase, harness: Harness) -> None:
    """S01 baseline: all fields set, error null, consistent with the wire."""
    check_pair_ok(harness.pair(pair), X25519, hrr=False, hrr_group=False)


def test_space_separated_options(pair: PairCase, harness: Harness) -> None:
    p = harness.pair(pair, form="space")
    check_pair_ok(p, X25519, hrr=False, hrr_group=False)


def test_default_mtu_is_accepted(pair: PairCase, harness: Harness) -> None:
    p = harness.pair(pair, client={"mtu": "default"}, server={"mtu": "default"})
    check_pair_ok(p, X25519, hrr=False, hrr_group=False)


def test_untrusted_server_fails(client_subject: Subject, harness: Harness, tmp_path) -> None:
    other = pki.generate(tmp_path / "other-pki")
    p = harness.pair(
        PairCase(client_subject.impl, client_subject.peer),
        server={"cert": str(other.server_cert), "key": str(other.server_key)},
    )
    assert p.client is not None and p.client.code == EXIT_FAIL, p.client and p.client.describe()
    check_protocol(p.client)
    if p.server.code is not None:
        assert p.server.code == EXIT_FAIL, p.server.describe()
        check_protocol(p.server)


def test_unsupported_configuration_exits_2(subject: Subject, harness: Harness) -> None:
    """Probes a rarely implemented group; skips where the library has it."""
    groups = f"{RARE_GROUP},{X25519}"
    extra = {"key_share": RARE_GROUP} if subject.role == CLIENT else {}
    opts = harness.options(subject.impl, subject.role, groups=groups, **extra)
    run = harness.run(subject.impl, subject.role, render(opts, "equals"), PROBE_TIMEOUT)
    if run.code != EXIT_UNSUPPORTED:
        assert run.code in (None, EXIT_OK, EXIT_FAIL), run.describe()
        pytest.skip(f"{subject.impl.id} supports {RARE_GROUP}")
    check_protocol(run)
    assert len(run.stdout) == 1, run.describe()
