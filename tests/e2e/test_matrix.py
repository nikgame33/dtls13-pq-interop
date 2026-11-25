"""Matrix cases through the real CLI, runner and proxy, against real OpenSSL and wolfSSL builds."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from dtls_interop.implementations import Implementation
from dtls_interop.records import HS_CLIENT_HELLO, parse_datagram
from dtls_interop.results import AdapterRecord, CaseResult, Outcome, read_run

CLI = Path(sys.executable).parent / "dtls-interop"
SPLIT_ROWS = ["S03+split", "S04+split", "S08+split", "S09+split"]
# Cases that end in a timeout only need a few retransmissions to show it.
SHORT_TIMEOUT = 6.0
SPLIT = "replaced: split CH1 into 2 fragments"

type Cases = dict[tuple[str, str, str], CaseResult]


def entry(record: AdapterRecord) -> str:
    """The matrix entry name, as in the case directory."""
    if record.variant == "default":
        return record.implementation
    return f"{record.implementation}+{record.variant}"


@pytest.fixture
def matrix(
    tmp_path: Path, require_impl: Callable[[str], Implementation]
) -> Callable[..., tuple[Cases, Path]]:
    def run(scenarios, clients, servers, *extra: str) -> tuple[Cases, Path]:
        for name in {*clients, *servers}:
            require_impl(name)
        results = tmp_path / "results"
        args = [f"--scenario={','.join(scenarios)}", f"--results-dir={results}", *extra]
        args += [f"--client={c}" for c in clients] + [f"--server={s}" for s in servers]
        proc = subprocess.run([str(CLI), "run", *args], capture_output=True, text=True, timeout=600)
        assert proc.returncode in (0, 1), proc.stdout + proc.stderr
        [run_dir] = [p for p in results.glob("*/*") if p.is_dir()]
        cases = {(c.scenario, entry(c.client), entry(c.server)): c for c in read_run(run_dir)}
        return cases, run_dir

    return run


def case_trace(run_dir: Path, case: CaseResult) -> list[dict]:
    pair = f"{entry(case.client)}__{entry(case.server)}"
    assert case.trace is not None
    text = (run_dir / case.scenario / pair / case.trace).read_text()
    return [json.loads(line) for line in text.splitlines()]


def delivered_ch1_fragments(trace: list[dict]) -> list[tuple[int, int, int]]:
    """(offset, length, message length) of CH1 fragments the proxy sent to the server."""
    out = []
    for d in trace:
        if d["direction"] != "c2s" or d["action"] not in ("forwarded", "delayed"):
            continue
        for f in parse_datagram(bytes.fromhex(d["payload"])).handshake_fragments():
            if f.msg_type == HS_CLIENT_HELLO and f.message_seq == 0:
                out.append((f.fragment_offset, f.fragment_length, f.length))
    return out


def test_reorder_and_loss_between_openssl_peers(matrix):
    cases, run_dir = matrix(["S08", "S09"], ["openssl"], ["openssl", "openssl+accept"])

    assert {k: c.outcome for k, c in cases.items()} == {
        (s, "openssl", srv): Outcome.PASS
        for s in ("S08", "S09")
        for srv in ("openssl", "openssl+accept")
    }, {k: c.reason for k, c in cases.items()}
    for (scenario, _, _), case in cases.items():
        assert case.path.proxied and case.path.pmtu == 1280 and case.path.split_ch1 is None
        # The client fragmented CH1 itself; the proxy only reordered or dropped.
        assert case.ch1_fragments == 2 and case.ch1_size > 1232
        if scenario == "S08":
            assert case.path.actions == {"delayed: reorder CH1 fragments": 2}
            offsets = [off for off, _, _ in delivered_ch1_fragments(case_trace(run_dir, case))]
            assert offsets[:2] == sorted(offsets[:2], reverse=True)
        else:
            assert case.path.actions == {"dropped: drop first CH1 fragment": 1}
            # The server first sees the second fragment; the first comes with the retransmission.
            first, *_ = delivered_ch1_fragments(case_trace(run_dir, case))
            assert first[0] > 0


def test_wolfssl_client_through_split_rows_to_openssl(matrix):
    cases, run_dir = matrix(SPLIT_ROWS, ["wolfssl"], ["openssl"])

    assert {k[0]: c.outcome for k, c in cases.items()} == dict.fromkeys(SPLIT_ROWS, Outcome.PASS), {
        k: c.reason for k, c in cases.items()
    }
    for case in cases.values():
        # The client sent one CH1 with the full share; the proxy split it.
        assert case.ch1_fragments == 1 and case.ch1_size > 1232
        assert case.path.split_ch1 == 2 and case.path.actions[SPLIT] >= 1
        assert case.path.pmtu == 1500 and "--mtu=1500" in case.server.command
        assert case.client.result is not None and case.client.result["hrr_group"] is False
        fragments = delivered_ch1_fragments(case_trace(run_dir, case))
        assert fragments and all(length < total for _, length, total in fragments)


def test_wolfssl_client_never_fragments_ch1_in_base_rows(matrix):
    # wolfSSL 5.9.4 would send an empty key_share instead of fragmenting CH1 (src/tls13.c),
    # so the adapter refuses the requested share with exit 2 before sending anything.
    cases, _ = matrix(["S03"], ["wolfssl"], ["openssl"])

    [case] = cases.values()
    assert case.path.actions == {}
    assert case.outcome is Outcome.UNSUPPORTED, case.reason
    assert "sends an empty key_share instead of fragmenting CH1" in case.reason
    assert case.ch1_size is None and case.duration_s < 2.0


def test_wolfssl_server_and_split_ch1(matrix):
    # wolfSSL 5.9.4 servers drop a fragmented CH1 statelessly, except accept-tls13 without cookie.
    rows = ["S03+split", "S04+split"]
    servers = ["wolfssl", "wolfssl+accept-tls13"]
    cases, _ = matrix(rows, ["wolfssl"], servers, f"--timeout={SHORT_TIMEOUT}")

    assert {(k[0], k[2]): c.outcome for k, c in cases.items()} == {
        ("S03+split", "wolfssl"): Outcome.TIMEOUT,
        ("S03+split", "wolfssl+accept-tls13"): Outcome.PASS,
        ("S04+split", "wolfssl"): Outcome.TIMEOUT,
        ("S04+split", "wolfssl+accept-tls13"): Outcome.TIMEOUT,
    }
    assert all(c.path.actions.get(SPLIT, 0) >= 1 for c in cases.values())


def test_unsupported_cases_end_promptly(matrix):
    # Server grace is 5 s; an unsupported side must not make the runner wait for it.
    cases, _ = matrix(["S05", "S07"], ["openssl", "wolfssl"], ["openssl", "wolfssl"])

    both = ["openssl", "wolfssl"]
    expected = {("S05", "openssl", s): Outcome.UNSUPPORTED for s in both}
    expected |= {("S05", "wolfssl", s): Outcome.PASS for s in both}
    expected |= {("S07", c, s): Outcome.UNSUPPORTED for c in both for s in both}
    assert {k: c.outcome for k, c in cases.items()} == expected
    for key, case in cases.items():
        if case.outcome is Outcome.UNSUPPORTED:
            assert case.duration_s < 2.0, (key, case.duration_s)


def test_resumption_and_tls_rows(matrix):
    servers = ["openssl", "openssl+accept", "wolfssl"]
    cases, run_dir = matrix(["S10", "T01"], ["openssl"], servers, f"--timeout={SHORT_TIMEOUT}")

    assert {(k[0], k[2]): c.outcome for k, c in cases.items()} == {
        ("S10", "openssl"): Outcome.PASS,
        ("S10", "openssl+accept"): Outcome.PASS,
        # wolfSSL servers drop a fragmented CH1 (implementations/wolfssl/README.md).
        ("S10", "wolfssl"): Outcome.TIMEOUT,
        ("T01", "openssl"): Outcome.PASS,
        # The listener variant is DTLS only.
        ("T01", "openssl+accept"): Outcome.UNSUPPORTED,
        ("T01", "wolfssl"): Outcome.PASS,
    }, {k: c.reason for k, c in cases.items()}
    for (scenario, _, _), case in cases.items():
        if case.outcome is not Outcome.PASS:
            continue
        assert case.cookie_echoed is True and case.path.proxied
        flows = {d["flow"] for d in case_trace(run_dir, case)}
        assert flows == ({0, 1} if scenario == "S10" else {0})
        assert case.client.result["resumed"] is (scenario == "S10")
