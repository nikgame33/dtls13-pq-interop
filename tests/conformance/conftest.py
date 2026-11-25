"""Parametrize the conformance suite over every discovered entry and variant (ADR 0002).

New adapters and variants are picked up from implementations/ without editing the suite.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from dtls_interop import implementations, pki

from .harness import Harness, PairCase, Subject, pair_cases, subjects

ENTRIES = implementations.discover()


def _subject_id(s: Subject) -> str:
    return f"{s.role}-{s.impl.id}"


def _pair_id(p: PairCase) -> str:
    return f"{p.client.id}--{p.server.id}"


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    params = {
        "subject": [(s, _subject_id(s)) for s in subjects(ENTRIES)],
        "client_subject": [(s, _subject_id(s)) for s in subjects(ENTRIES, "client")],
        "server_subject": [(s, _subject_id(s)) for s in subjects(ENTRIES, "server")],
        "pair": [(p, _pair_id(p)) for p in pair_cases(ENTRIES)],
    }
    for name, values in params.items():
        if name in metafunc.fixturenames:
            metafunc.parametrize(
                name, [v for v, _ in values], ids=[i for _, i in values], indirect=True
            )


def _built(request: pytest.FixtureRequest, *impls: implementations.Implementation) -> None:
    require = request.getfixturevalue("require_impl")
    for impl in impls:
        require(impl.id)


@pytest.fixture
def subject(request: pytest.FixtureRequest) -> Subject:
    _built(request, request.param.impl)
    return request.param


@pytest.fixture
def client_subject(request: pytest.FixtureRequest) -> Subject:
    _built(request, request.param.impl)
    return request.param


@pytest.fixture
def server_subject(request: pytest.FixtureRequest) -> Subject:
    _built(request, request.param.impl)
    return request.param


@pytest.fixture
def pair(request: pytest.FixtureRequest) -> PairCase:
    _built(request, request.param.client, request.param.server)
    return request.param


@pytest.fixture
def harness(test_pki: pki.TestPki, tmp_path: Path) -> Iterator[Harness]:
    h = Harness(test_pki, tmp_path)
    yield h
    h.close()
