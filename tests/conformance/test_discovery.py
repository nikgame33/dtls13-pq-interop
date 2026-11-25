"""The suite's case generation follows discovery, so new adapters and variants need no edits."""

from __future__ import annotations

from pathlib import Path

from echo_adapter import install

from dtls_interop import implementations

from .harness import pair_cases, subjects


def _discover(root: Path) -> list[implementations.Implementation]:
    install(root, "alpha", variants="server accept: server only\nclient slow: client only\n")
    install(root, "beta", built=False, variants="both strict: either role\n")
    return implementations.discover(root / "implementations", root / "build")


def test_subjects_respect_variant_roles(tmp_path: Path) -> None:
    got = {(s.role, s.impl.id, s.peer.id) for s in subjects(_discover(tmp_path))}
    assert got == {
        ("client", "alpha", "alpha"),
        ("server", "alpha", "alpha"),
        ("server", "alpha+accept", "alpha"),
        ("client", "alpha+slow", "alpha"),
        ("client", "beta", "beta"),
        ("server", "beta", "beta"),
        ("client", "beta+strict", "beta"),
        ("server", "beta+strict", "beta"),
    }


def test_subjects_by_role(tmp_path: Path) -> None:
    got = {s.impl.id for s in subjects(_discover(tmp_path), "server")}
    assert got == {"alpha", "alpha+accept", "beta", "beta+strict"}


def test_pair_cases_cover_every_variant_once_per_role(tmp_path: Path) -> None:
    got = [(c.client.id, c.server.id) for c in pair_cases(_discover(tmp_path))]
    assert sorted(got) == sorted(
        [
            ("alpha", "alpha"),
            ("alpha", "alpha+accept"),
            ("alpha+slow", "alpha"),
            ("beta", "beta"),
            ("beta", "beta+strict"),
            ("beta+strict", "beta"),
        ]
    )
