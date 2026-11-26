from __future__ import annotations

import pytest
from echo_adapter import install

from dtls_interop import implementations
from dtls_interop.implementations import BOTH_ROLES, read_transports, read_variants


def discover(root):
    return implementations.discover(root / "implementations", root / "build")


def test_one_entry_per_variant_default_first(tmp_path):
    install(tmp_path, "lib", variants="server b-path: Second\n\nboth a.path: First\n")
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
    assert [e.roles for e in entries[:3]] == [BOTH_ROLES, {"server"}, BOTH_ROLES]
    # Variants share the adapter and the build.
    assert {e.adapter for e in entries[:3]} == {entries[0].adapter}
    assert all(e.is_built for e in entries[:3])
    assert entries[0].version == "udp-echo 1.0"
    assert not entries[3].is_built and entries[3].version is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("client nocolon\n", "expected 'ROLE NAME: description'"),
        ("client x:\n", "expected 'ROLE NAME: description'"),
        ("x: no role\n", "expected 'ROLE NAME: description'"),
        ("peer x: unknown role\n", "expected 'ROLE NAME: description'"),
        ("client bad name: d\n", "expected 'ROLE NAME: description'"),
        ("both a+b: d\n", "expected 'ROLE NAME: description'"),
        ("both default: d\n", "duplicate or reserved variant 'default'"),
        ("client a: one\nserver a: two\n", "duplicate or reserved variant 'a'"),
    ],
)
def test_malformed_variants_file(tmp_path, text, message):
    path = tmp_path / "variants"
    path.write_text(text)

    with pytest.raises(ValueError, match=message):
        read_variants(path)


def test_missing_variants_file_means_none(tmp_path):
    assert read_variants(tmp_path / "variants") == []


def test_transports_are_declared_per_implementation(tmp_path):
    install(tmp_path, "both", variants="server alt: Alt\n", transports="dtls\ntls\n")
    install(tmp_path, "legacy", transports=None)
    install(tmp_path, "tlsonly", transports="tls\n")

    found = {e.id: e.transports for e in discover(tmp_path)}

    assert found == {
        "both": {"dtls", "tls"},
        "both+alt": {"dtls", "tls"},  # variants share the adapter, so its transports
        "legacy": {"dtls"},
        "tlsonly": {"tls"},
    }


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("quic\n", "unknown or duplicate transport 'quic'"),
        ("tls\ntls\n", "unknown or duplicate transport 'tls'"),
        ("\n", "lists no transport"),
    ],
)
def test_malformed_transports_file(tmp_path, text, message):
    path = tmp_path / "transports"
    path.write_text(text)

    with pytest.raises(ValueError, match=message):
        read_transports(path)


def test_shipped_transports_files_are_valid():
    for impl in implementations.discover():
        assert impl.transports <= implementations.KNOWN_TRANSPORTS
