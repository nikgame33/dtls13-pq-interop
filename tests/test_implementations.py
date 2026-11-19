from __future__ import annotations

import pytest
from echo_adapter import install

from dtls_interop import implementations
from dtls_interop.implementations import read_variants


def discover(root):
    return implementations.discover(root / "implementations", root / "build")


def test_one_entry_per_variant_default_first(tmp_path):
    install(tmp_path, "lib", variants="b-path: Second\n\na.path: First\n")
    install(tmp_path, "other", built=False)

    entries = discover(tmp_path)

    assert [(e.id, e.name, e.variant) for e in entries] == [
        ("lib", "lib", "default"),
        ("lib+b-path", "lib", "b-path"),
        ("lib+a.path", "lib", "a.path"),
        ("other", "other", "default"),
    ]
    assert entries[1].variant_description == "Second"
    assert entries[0].variant_description is None
    # Variants share the adapter and the build.
    assert {e.adapter for e in entries[:3]} == {entries[0].adapter}
    assert all(e.is_built for e in entries[:3])
    assert entries[0].version == "udp-echo 1.0"
    assert not entries[3].is_built and entries[3].version is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("nocolon\n", "expected 'NAME: description'"),
        ("x:\n", "expected 'NAME: description'"),
        ("bad name: d\n", "expected 'NAME: description'"),
        ("a+b: d\n", "expected 'NAME: description'"),
        ("default: d\n", "duplicate or reserved variant 'default'"),
        ("a: one\na: two\n", "duplicate or reserved variant 'a'"),
    ],
)
def test_malformed_variants_file(tmp_path, text, message):
    path = tmp_path / "variants"
    path.write_text(text)

    with pytest.raises(ValueError, match=message):
        read_variants(path)


def test_missing_variants_file_means_none(tmp_path):
    assert read_variants(tmp_path / "variants") == []
