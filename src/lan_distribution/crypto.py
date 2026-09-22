"""Server and per-client X.509 identities."""

import datetime as dt
import ipaddress
import os
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def private_bytes(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def public_fingerprint(cert: x509.Certificate) -> str:
    return "SHA256:" + cert.fingerprint(hashes.SHA256()).hex().upper()


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def generate_server(state: Path) -> str:
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    identity = state / "server-id"
    if identity.exists():
        return identity.read_text().strip()
    if any(state.iterdir()):
        raise ValueError("server state is incomplete; refusing to replace identity")
    server_id = str(uuid.uuid4())
    now = dt.datetime.now(dt.UTC)
    tls_key = ed25519.Ed25519PrivateKey.generate()
    ca_key = ed25519.Ed25519PrivateKey.generate()
    tls_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"lan-distribution {server_id}")])
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"lan-distribution client CA {server_id}")]
    )
    tls_cert = (
        x509.CertificateBuilder()
        .subject_name(tls_name)
        .issuer_name(tls_name)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("lan-distribution.local"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(tls_key, None)
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, True, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, None)
    )
    write_private(state / "tls-key.pem", private_bytes(tls_key))
    write_private(state / "client-ca-key.pem", private_bytes(ca_key))
    (state / "tls-cert.pem").write_bytes(tls_cert.public_bytes(serialization.Encoding.PEM))
    (state / "client-ca-cert.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    identity.write_text(server_id + "\n")
    identity.chmod(0o600)
    return server_id


def new_client_key_csr(client_id: str) -> tuple[bytes, bytes]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, None)
    return private_bytes(key), csr.public_bytes(serialization.Encoding.PEM)


def sign_client_csr(state: Path, csr_pem: bytes, client_id: str) -> bytes:
    if len(csr_pem) > 8192:
        raise ValueError("invalid CSR")
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid or not isinstance(csr.public_key(), ed25519.Ed25519PublicKey):
        raise ValueError("invalid CSR")
    if (
        len(csr.subject) != 1
        or csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != client_id
        or list(csr.extensions)
    ):
        raise ValueError("CSR client ID mismatch")
    key = serialization.load_pem_private_key((state / "client-ca-key.pem").read_bytes(), None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("invalid client CA key")
    ca = x509.load_pem_x509_certificate((state / "client-ca-cert.pem").read_bytes())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM)
