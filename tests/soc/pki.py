"""Throw-away test PKI (EC keys) for exercising real mutual-TLS handshakes offline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write(path: Path, key, cert) -> None:
    path.with_suffix(".key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".key").chmod(0o600)


def make_ca(directory: Path, name: str = "test-ca"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(_name(name))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    _write(directory / name, key, cert)
    return key, cert, directory / f"{name}.crt"


def issue(directory: Path, ca_key, ca_cert, common_name: str, *, server: bool, client: bool,
          hosts: tuple[str, ...] = ()):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    usages = []
    if server:
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    sans = []
    for host in hosts:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    builder = (x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(ca_cert.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.ExtendedKeyUsage(usages), critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    _write(directory / common_name, key, cert)
    return directory / f"{common_name}.crt", directory / f"{common_name}.key"
