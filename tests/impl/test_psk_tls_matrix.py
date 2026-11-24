"""S10 and T01 end to end through the runner: real adapters, real UDP/TCP, the harness proxies.

Covers every pair of the OpenSSL and wolfSSL entries, so cross-library resumption and the TLS
cookie echo are measured the way `dtls-interop run` measures them, plus the proxy trace.
"""

from __future__ import annotations

import dataclasses
import json
from contextlib import AbstractContextManager

import pytest

from dtls_interop import runner, scenarios
from dtls_interop.proxy import UdpProxy
from dtls_interop.results import Outcome, RunLayout
from dtls_interop.scenarios import X25519, PathConditions, Scenario

CLIENTS = ["openssl", "wolfssl"]
SERVERS = ["openssl", "openssl+accept", "wolfssl", "wolfssl+accept-tls13"]
DTLS_ONLY = {"openssl+accept", "wolfssl+accept-tls13"}
LIMITS = {"ready_timeout": 10.0, "case_timeout": 12.0, "server_grace": 5.0}
# Library findings (README of each adapter); strict, so a fixed library shows up as XPASS.
S10_KNOWN = {
    ("openssl", "wolfssl"): "wolfSSL servers drop a fragmented CH1 (also without a cookie)",
    ("openssl", "wolfssl+accept-tls13"): "wolfSSL servers drop a fragmented CH1",
}
STALL = "wolfSSL client stalls resuming after an OpenSSL cookie HRR"
COOKIE_RESUME_KNOWN = {("wolfssl", "openssl"): STALL, ("wolfssl", "openssl+accept"): STALL}


def udp_path(server: tuple[str, int], conditions: PathConditions) -> AbstractContextManager:
    if conditions.impairments:
        raise ValueError(f"impairments not used here: {conditions.impairments}")
    return UdpProxy(server, pmtu=conditions.pmtu)


def run(require_impl, test_pki, tmp_path, scenario_id: str | Scenario, client: str, server: str):
    scenario = scenarios.get(scenario_id) if isinstance(scenario_id, str) else scenario_id
    layout = RunLayout.new(tmp_path / "results")
    result = runner.run_case(
        scenario,
        require_impl(client),
        require_impl(server),
        layout=layout,
        pki=test_pki,
        path_factory=udp_path,
        **LIMITS,
    )
    case_dir = layout.case_dir(scenario.id, client, server)
    trace_file = case_dir / "trace.jsonl"
    lines = trace_file.read_text().splitlines() if trace_file.exists() else []
    return result, [json.loads(line) for line in lines]


@pytest.mark.parametrize("server", SERVERS)
@pytest.mark.parametrize("client", CLIENTS)
def test_s10_resumption_after_cookie_hrr_at_pmtu_1280(
    request, require_impl, test_pki, tmp_path, client, server
):
    known = S10_KNOWN.get((client, server))
    if known:
        request.applymarker(pytest.mark.xfail(reason=known, strict=True))
    result, trace = run(require_impl, test_pki, tmp_path, "S10", client, server)

    if client == "wolfssl":
        # The X25519MLKEM768 CH1 does not fit at 1280 and wolfSSL would empty the share instead
        # of fragmenting it, so the adapter refuses S10's explicit share (README).
        assert result.outcome is Outcome.UNSUPPORTED, result.reason
        assert "empty key_share" in result.reason
        return
    assert result.outcome is Outcome.PASS, result.reason
    for side in (result.client.result, result.server.result):
        assert side["resumed"] is True and side["hrr_cookie"] is True
    # Two connections from two client ports, each with a cookie HRR that CH2 echoed.
    assert {d["flow"] for d in trace} == {0, 1}
    assert result.cookie_echoed is True
    assert all(d["size"] <= 1232 for d in trace if d["action"] == "forwarded")


def _x25519(scenario: Scenario) -> Scenario:
    """S10 without PQ and fragmentation: resumption after a cookie HRR alone."""
    client = dataclasses.replace(scenario.client, groups=(X25519,), key_share=X25519, mtu=1500)
    server = dataclasses.replace(scenario.server, groups=(X25519,), mtu=1500)
    expected = dataclasses.replace(scenario.expected, group=X25519)
    return dataclasses.replace(
        scenario, client=client, server=server, path=PathConditions(pmtu=1500), expected=expected
    )


@pytest.mark.parametrize("server", SERVERS)
@pytest.mark.parametrize("client", CLIENTS)
def test_resumption_after_cookie_hrr_x25519(
    request, require_impl, test_pki, tmp_path, client, server
):
    known = COOKIE_RESUME_KNOWN.get((client, server))
    if known:
        request.applymarker(pytest.mark.xfail(reason=known, strict=True))
    result, trace = run(
        require_impl, test_pki, tmp_path, _x25519(scenarios.get("S10")), client, server
    )

    assert result.outcome is Outcome.PASS, result.reason
    assert result.client.result["resumed"] is True and result.server.result["resumed"] is True
    assert {d["flow"] for d in trace} == {0, 1}
    assert result.cookie_echoed is True


@pytest.mark.parametrize("server", SERVERS)
@pytest.mark.parametrize("client", CLIENTS)
def test_t01_tls_cookie_echo(require_impl, test_pki, tmp_path, client, server):
    result, trace = run(require_impl, test_pki, tmp_path, "T01", client, server)

    if server in DTLS_ONLY:
        assert result.outcome is Outcome.UNSUPPORTED, result.reason
        assert result.server.exit_code == 2 and not result.client.started
        return
    assert result.outcome is Outcome.PASS, result.reason
    assert result.path.proxied is True
    assert result.cookie_echoed is True
    for side in (result.client.result, result.server.result):
        assert side["version"] == "TLSv1.3" and side["hrr_cookie"] is True
    assert {s["flow"] for s in trace} == {0}
