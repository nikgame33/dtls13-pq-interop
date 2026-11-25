"""The harness's own handling of misbehaving adapters, driven by the UDP echo test adapter."""

from __future__ import annotations

from pathlib import Path

import pytest
from echo_adapter import install

from . import harness as harness_module
from .harness import Harness, PairCase


def _pair(harness: Harness, root: Path, *flags: str, **server: str) -> None:
    impl = install(root, "echo", *flags)
    harness.pair(PairCase(impl, impl), server=server)


def test_server_unsupported_before_ready_skips(harness: Harness, tmp_path: Path) -> None:
    with pytest.raises(pytest.skip.Exception, match="server reports unsupported"):
        _pair(harness, tmp_path, "--behave=exit2")


def test_server_usage_error_before_ready_fails(harness: Harness, tmp_path: Path) -> None:
    with pytest.raises(pytest.fail.Exception, match=r"rejected its options \(exit 64\)"):
        _pair(harness, tmp_path, mtu="abc")


def test_server_without_ready_line_fails(
    harness: Harness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness_module, "READY_TIMEOUT", 0.5)
    with pytest.raises(pytest.fail.Exception, match="no ready line"):
        _pair(harness, tmp_path, "--behave=never-ready")
