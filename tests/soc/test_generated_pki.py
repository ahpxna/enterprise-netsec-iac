"""The shipped PKI generator must satisfy STRICT X.509 verification (Python >= 3.13's default)."""

import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None or shutil.which("bash") is None, reason="needs openssl and bash")

LEAVES = {
    "elasticsearch": "ca", "kibana": "ca", "logstash": "ca", "soc-ai-api": "ca", "soc-response": "ca",
    "enforcer-fw-core": "ca", "enforcer-fw-dmz": "ca", "vyos-api-fw-core": "ca", "vyos-api-fw-dmz": "ca",
    "soc-enrichment": "ai-client-ca", "soc-decision": "decision-ca",
}


def generate(cert_dir: Path) -> str:
    done = subprocess.run(["bash", str(ROOT / "scripts/gen_soc_certs.sh")], env={**os.environ, "SOC_CERT_DIR": str(cert_dir)},
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    return done.stdout


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    directory = tmp_path_factory.mktemp("socpki")
    generate(directory)
    return directory


def strict_verify(cert: Path, ca: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", "verify", "-x509_strict", "-CAfile", str(ca), str(cert)], capture_output=True, text=True)


@pytest.mark.parametrize("leaf, ca", sorted(LEAVES.items()))
def test_every_generated_leaf_passes_strict_verification(pki, leaf, ca):
    done = strict_verify(pki / f"{leaf}.crt", pki / f"{ca}.crt")
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_ca_declares_certificate_signing_usage(pki):
    for ca in ("ca", "ai-client-ca", "decision-ca"):
        text = subprocess.run(["openssl", "x509", "-in", str(pki / f"{ca}.crt"), "-noout", "-text"], capture_output=True, text=True).stdout
        assert "Certificate Sign" in text and "CA:TRUE" in text and "Subject Key Identifier" in text, ca


def test_a_strict_python_tls_handshake_succeeds_with_a_generated_certificate(pki):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(pki / "elasticsearch.crt", pki / "elasticsearch.key")
    client = ssl.create_default_context(cafile=str(pki / "ca.crt"))
    client.verify_flags |= ssl.VERIFY_X509_STRICT                      # the default since Python 3.13; explicit so 3.11/3.12 test it too
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    seen = {}

    def serve():
        conn, _ = listener.accept()
        try:
            with server.wrap_socket(conn, server_side=True) as tls:
                seen["version"] = tls.version()
                tls.sendall(b"ok")
        except ssl.SSLError as exc:
            seen["error"] = str(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, client.wrap_socket(raw, server_hostname="localhost") as tls:
        assert tls.recv(2) == b"ok"
    thread.join(5)
    listener.close()
    assert "error" not in seen and seen["version"].startswith("TLS")


def test_a_second_run_changes_nothing(pki):
    before = {p.name: p.read_bytes() for p in pki.glob("*.crt")}
    output = generate(pki)
    assert "generated" not in output and "rotating" not in output
    assert before == {p.name: p.read_bytes() for p in pki.glob("*.crt")}


def test_an_old_ca_without_key_usage_is_rotated_and_everything_it_signed_is_reissued(tmp_path):
    generate(tmp_path)
    old = tmp_path / "ca.crt"
    subprocess.run(["openssl", "req", "-x509", "-key", str(tmp_path / "ca.key"), "-subj", "/CN=CompanyXYZ SOC Analytics CA", "-days", "825",
                    "-sha256", "-out", str(old)], check=True, capture_output=True)
    assert strict_verify(tmp_path / "elasticsearch.crt", old).returncode != 0          # the legacy shape is rejected
    output = generate(tmp_path)
    assert "rotating CompanyXYZ SOC Analytics CA" in output and "restart the SOC services" in output
    for leaf, ca in LEAVES.items():
        assert strict_verify(tmp_path / f"{leaf}.crt", tmp_path / f"{ca}.crt").returncode == 0, leaf
