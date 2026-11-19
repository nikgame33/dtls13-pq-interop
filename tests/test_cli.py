"""CLI tests through the installed console script and `python -m`, against the echo adapter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from echo_adapter import ECHO_VERSION, install

from dtls_interop.results import Outcome, read_result, read_run

CONSOLE_SCRIPT = Path(sys.executable).parent / "dtls-interop"


@pytest.fixture
def impl_root(tmp_path: Path) -> Path:
    install(tmp_path, "echo-a")
    install(tmp_path, "echo-b")
    install(tmp_path, "echo-unbuilt", built=False)
    return tmp_path


def cli(root: Path, *args: str, module: bool = False) -> subprocess.CompletedProcess[str]:
    entry = [sys.executable, "-m", "dtls_interop.cli"] if module else [str(CONSOLE_SCRIPT)]
    dirs = [f"--implementations-dir={root / 'implementations'}", f"--build-dir={root / 'build'}"]
    command, *rest = args
    return subprocess.run(
        [*entry, command, *dirs, *rest], capture_output=True, text=True, timeout=120
    )


def run_dirs(results: Path) -> list[Path]:
    return sorted(p for p in results.glob("*/*") if p.is_dir())


@pytest.mark.parametrize("module", [False, True], ids=["console-script", "python-m"])
def test_list(impl_root, module):
    proc = cli(impl_root, "list", module=module)

    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert f"  echo-a        built ({ECHO_VERSION})" in lines
    assert "  echo-unbuilt  not built" in lines
    assert "  S01  X25519, full share, PMTU 1500, no validation" in lines
    assert any(line.startswith("  T01  ") for line in lines)


def test_run_all_built_pairs(impl_root, tmp_path):
    results = tmp_path / "results"
    proc = cli(impl_root, "run", "--scenario=S01", f"--results-dir={results}")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    [run_dir] = run_dirs(results)
    cases = read_run(run_dir)
    built = ("echo-a", "echo-b")
    assert [(c.client.implementation, c.server.implementation) for c in cases] == [
        (c, s) for c in built for s in built
    ]
    assert {c.outcome for c in cases} == {Outcome.PASS}
    assert all(c.run_id == run_dir.name for c in cases)
    assert (run_dir / "pki" / "ca.pem").is_file()
    assert "S01  echo-a__echo-b  pass" in proc.stdout
    assert "4/4 cases passed or unsupported" in proc.stdout


def test_run_exit_code(impl_root, tmp_path):
    install(impl_root, "echo-fail", "--behave=fail")
    results = tmp_path / "results"
    ok = cli(
        impl_root,
        "run",
        "--scenario=S01",
        "--client=echo-a",
        "--server=echo-b",
        f"--results-dir={results}",
    )
    failed = cli(
        impl_root,
        "run",
        "--scenario",
        "S01",
        "--client",
        "echo-fail",
        "--server",
        "echo-a",
        "--results-dir",
        str(results),
    )

    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert "S01  echo-fail__echo-a  fail  " in failed.stdout
    case = next(results.glob("*/*/S01/echo-fail__echo-a/result.json"))
    assert read_result(case).outcome is Outcome.FAIL


def test_run_impaired_scenario_without_proxy_fails(impl_root, tmp_path):
    results = tmp_path / "results"
    proc = cli(
        impl_root,
        "run",
        "--scenario=s08",
        "--client=echo-a",
        "--server=echo-a",
        f"--results-dir={results}",
    )

    assert proc.returncode == 1
    assert "S08  echo-a__echo-a  error" in proc.stdout
    assert "path impairments not available" in proc.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--scenario=S99"], "unknown scenario 'S99'"),
        (["--scenario=S01", "--client=nope"], "unknown client implementation 'nope'"),
        (["--scenario=S01", "--server=echo-unbuilt"], "'echo-unbuilt' is not built"),
    ],
)
def test_run_usage_errors(impl_root, tmp_path, args, message):
    proc = cli(impl_root, "run", *args, f"--results-dir={tmp_path / 'results'}")

    assert proc.returncode == 2
    assert message in proc.stderr
    assert not (tmp_path / "results").exists()


def test_run_requires_scenario(impl_root):
    proc = cli(impl_root, "run")

    assert proc.returncode == 2
    assert "--scenario" in proc.stderr


def test_variants_are_listed_and_selectable(impl_root, tmp_path):
    install(impl_root, "echo-v", variants="alt: Alternative code path\n\nslow: Slow path\n")
    listing = cli(impl_root, "list")

    assert listing.returncode == 0, listing.stderr
    assert f"  echo-v+alt    built ({ECHO_VERSION})  variant: Alternative code path" in (
        listing.stdout.splitlines()
    )
    assert "  echo-v+slow   built" in listing.stdout

    results = tmp_path / "results"
    proc = cli(
        impl_root,
        "run",
        "--scenario=S01",
        "--client=echo-v+alt",
        "--server=echo-v,echo-v+slow",
        f"--results-dir={results}",
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "S01  echo-v+alt__echo-v+slow  pass" in proc.stdout
    [run_dir] = run_dirs(results)
    cases = read_run(run_dir)
    assert [(c.client.variant, c.server.variant) for c in cases] == [
        ("alt", "default"),
        ("alt", "slow"),
    ]


def test_malformed_variants_file_is_usage_error(impl_root):
    install(impl_root, "echo-bad", variants="no description here\n")
    proc = cli(impl_root, "list")

    assert proc.returncode == 2
    assert "expected 'NAME: description'" in proc.stderr
