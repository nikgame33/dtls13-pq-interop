"""Throwaway test PKI: one ECDSA P-256 CA and one server leaf for "localhost"."""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVER_NAME = "localhost"


@dataclass(frozen=True)
class TestPki:
    ca_cert: Path
    server_cert: Path
    server_key: Path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    # PKCS#8 PEM is the one key format every adapter's library reads.
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def generate(directory: Path) -> TestPki:
    """Create CA and server cert/key PEM files in `directory`."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.UTC)
    validity = (now - datetime.timedelta(hours=1), now + datetime.timedelta(days=7))

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("dtls-interop test CA"))
        .issuer_name(_name("dtls-interop test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(validity[0])
        .not_valid_after(validity[1])
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(SERVER_NAME))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(validity[0])
        .not_valid_after(validity[1])
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(SERVER_NAME),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    pki = TestPki(
        ca_cert=directory / "ca.pem",
        server_cert=directory / "server.pem",
        server_key=directory / "server.key",
    )
    pki.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    pki.server_cert.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(leaf_key, pki.server_key)
    return pki
