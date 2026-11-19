import subprocess

from dtls_interop import pki


def test_leaf_verifies_against_ca_with_openssl_cli(test_pki: pki.TestPki) -> None:
    # Verify with an independent X.509 implementation, the same way a TLS stack would.
    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(test_pki.ca_cert),
            "-purpose",
            "sslserver",
            "-verify_hostname",
            pki.SERVER_NAME,
            str(test_pki.server_cert),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith(": OK")


def test_key_matches_certificate(test_pki: pki.TestPki) -> None:
    def pubkey(args: list[str]) -> str:
        return subprocess.run(
            ["openssl", *args, "-pubout"], capture_output=True, text=True, check=True
        ).stdout

    from_cert = subprocess.run(
        ["openssl", "x509", "-in", str(test_pki.server_cert), "-pubkey", "-noout"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert pubkey(["pkey", "-in", str(test_pki.server_key)]) == from_cert
