from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from dtls_interop import implementations, pki


@pytest.fixture(scope="session")
def test_pki(tmp_path_factory: pytest.TempPathFactory) -> pki.TestPki:
    return pki.generate(tmp_path_factory.mktemp("pki"))


def _require_built(name: str) -> implementations.Implementation:
    by_name = {i.id: i for i in implementations.discover()}
    impl = by_name.get(name)
    # Requiring an implementation also requires all its variants.
    base = name.partition(implementations.VARIANT_SEPARATOR)[0]
    required = bool({name, base} & implementations.required_names())
    if impl is None or not impl.is_built:
        reason = f"{name} not built (run implementations/{base}/build.sh)"
        if required:
            pytest.fail(f"{reason}, but {implementations.REQUIRED_ENV} requires it")
        pytest.skip(reason)
    return impl


@pytest.fixture
def require_impl() -> Callable[[str], implementations.Implementation]:
    """Look up a built implementation; skip if unbuilt, fail if DTLS_INTEROP_REQUIRE names it."""
    return _require_built


@pytest.fixture
def repo_root() -> Path:
    return implementations.REPO_ROOT
