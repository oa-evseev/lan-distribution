import json
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from lan_distribution.client import Client, ClientError, RegistrationClosed, probe
from lan_distribution.config import ClientConfig, DatasetConfig, ServerConfig
from lan_distribution.crypto import new_client_key_csr, sign_client_csr
from lan_distribution.datasets import extract_verified, publish, validate_manifest
from lan_distribution.server import DistributionServer, control, initialize


@pytest.fixture
def live(tmp_path: Path):
    source = tmp_path / "source"
    shared = source / "shared-config"
    hidden = source / "hidden"
    shared.mkdir(parents=True)
    hidden.mkdir()
    (shared / "hello.txt").write_text("one")
    (hidden / "secret.txt").write_text("secret")
    config = ServerConfig(
        state_dir=tmp_path / "server",
        runtime_dir=tmp_path / "run",
        source_root=source,
        host="127.0.0.1",
        port=0,
        discovery=False,
        datasets={"shared-config": shared, "hidden": hidden},
    )
    server = DistributionServer(config, control_enabled=False)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    try:
        yield server, tmp_path, shared
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_full_lifecycle(live, monkeypatch):
    server, root, source = live
    url = f"https://127.0.0.1:{server.server_address[1]}"
    identity, fingerprint = probe(url)
    assert identity["server_id"] == server.server_id
    assert fingerprint.startswith("SHA256:")
    target = root / "target"
    client = Client(ClientConfig(root / "client", 1, {"shared-config": DatasetConfig(target)}))
    client.save_trust(identity)
    sent = []
    original_request = client.request

    def capture(method, path, payload=None, authenticated=True):
        if path == "/v1/enroll":
            sent.append(payload)
        return original_request(method, path, payload, authenticated)

    monkeypatch.setattr(client, "request", capture)
    assert server.remaining() == 0
    assert client.request("GET", "/v1/datasets", authenticated=False)[0] == 403
    with pytest.raises(RegistrationClosed):
        client.enroll("synthetic-client")
    server.open(120)
    assert server.remaining() > 0
    client_id = client.enroll("synthetic-client")
    assert sent[0]["csr"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert "PRIVATE KEY" not in str(sent)
    assert client.credentials() is not None
    assert client_id
    server.close_window()
    assert server.remaining() == 0
    assert client.request("GET", "/v1/datasets")[0] == 200
    client.reconnect(url)
    assert client.trust()["server_id"] == server.server_id
    assert client.sync() == {"shared-config": True}
    assert (target / "hello.txt").read_text() == "one"
    first = (root / "client/datasets/shared-config/current").readlink()
    assert client.sync() == {"shared-config": False}
    target.unlink()
    assert client.sync() == {"shared-config": False}
    assert (target / "hello.txt").read_text() == "one"
    (source / "hello.txt").write_text("two")
    assert client.sync() == {"shared-config": True}
    assert (target / "hello.txt").read_text() == "two"
    assert (root / "client/datasets/shared-config/current").readlink() != first
    assert client.sync() == {"shared-config": False}
    old_key = client.credentials()[1].read_bytes()
    client.rotate()
    assert client.credentials()[1].read_bytes() != old_key
    assert server.remaining() == 0
    with pytest.raises(ClientError, match="HTTP 403"):
        client.sync_one("missing", DatasetConfig())
    server.shutdown()
    server.server_close()
    with pytest.raises((OSError, ClientError)):
        client.sync()
    assert (target / "hello.txt").read_text() == "two"
    restarted = DistributionServer(
        replace(server.config, port=server.server_address[1]), control_enabled=False
    )
    thread = threading.Thread(target=restarted.start, daemon=True)
    thread.start()
    try:
        assert restarted.remaining() == 0
        (source / "hello.txt").write_text("three")
        assert client.sync() == {"shared-config": True}
        assert (target / "hello.txt").read_text() == "three"
        assert len(list((root / "client/datasets/shared-config/versions").iterdir())) == 2
    finally:
        restarted.shutdown()
        restarted.server_close()
        thread.join(timeout=3)


def test_disabled_and_wrong_server(live):
    server, root, _ = live
    identity, _ = probe(f"https://127.0.0.1:{server.server_address[1]}")
    client = Client(ClientConfig(root / "client"))
    client.save_trust(identity)
    unknown = Client(ClientConfig(root / "unknown"))
    unknown.save_trust(identity)
    unknown_id = "00000000-0000-4000-8000-000000000001"
    unknown_key, unknown_csr = new_client_key_csr(unknown_id)
    unknown_cert = sign_client_csr(server.config.state_dir, unknown_csr, unknown_id)
    unknown_ca = (server.config.state_dir / "client-ca-cert.pem").read_bytes()
    unknown._install_credentials(unknown_key, unknown_cert, unknown_ca, unknown_id)
    assert unknown.request("GET", "/v1/datasets")[0] == 403
    server.open(20)
    client_id = client.enroll("synthetic-client")
    assert client.request("GET", "/v1/datasets")[0] == 200
    old_server_id = server.server_id
    server.server_id = "wrong-id"
    with pytest.raises(ClientError, match="server ID changed"):
        client.request("GET", "/v1/datasets")
    server.server_id = old_server_id
    with server.db() as db:
        db.execute("UPDATE clients SET status='disabled' WHERE id=?", (client_id,))
    assert client.request("GET", "/v1/datasets")[0] == 403
    with server.db() as db:
        db.execute("UPDATE clients SET status='enabled' WHERE id=?", (client_id,))
    assert client.request("GET", "/v1/datasets")[0] == 200
    with server.db() as db:
        db.execute("UPDATE clients SET status='revoked' WHERE id=?", (client_id,))
    assert client.request("GET", "/v1/datasets")[0] == 403
    identity["server_id"] = "different"
    with pytest.raises(ClientError):
        client.save_trust(identity)


def test_published_snapshot_is_pinned_and_authorized(tmp_path):
    source = tmp_path / "published-source"
    source.mkdir()
    (source / "cert.pem").write_text("certificate-a")
    (source / "key.pem").write_text("private-a")
    (source / "key.pem").chmod(0o600)
    config = ServerConfig(
        state_dir=tmp_path / "server",
        runtime_dir=tmp_path / "run",
        source_root=tmp_path,
        host="127.0.0.1",
        port=0,
        discovery=False,
        datasets={"test-pki": None},
    )
    initialize(config)
    version_a, _ = publish(config.state_dir, "test-pki", source)
    server = DistributionServer(config, control_enabled=False)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    try:
        client = Client(ClientConfig(tmp_path / "client"))
        client.save_trust(probe(f"https://127.0.0.1:{server.server_address[1]}")[0])
        server.open(20)
        client_id = client.enroll("published-test")
        server.close_window()
        status, body = client.request("GET", "/v1/datasets/test-pki/manifest")
        assert status == 200
        manifest_a = json.loads(body)
        validate_manifest(manifest_a)
        assert manifest_a["version"] == version_a

        (source / "cert.pem").write_text("certificate-b")
        version_b, changed = publish(config.state_dir, "test-pki", source)
        assert changed and version_b != version_a
        status, archive_a = client.request(
            "GET", f"/v1/datasets/test-pki/archive/{manifest_a['version']}"
        )
        assert status == 200
        replica = tmp_path / "replica-a"
        extract_verified(archive_a, manifest_a, replica)
        assert (replica / "cert.pem").read_text() == "certificate-a"
        assert (replica / "key.pem").read_text() == "private-a"

        with server.db() as db:
            db.execute("DELETE FROM grants WHERE client_id=? AND dataset='test-pki'", (client_id,))
        assert client.request("GET", "/v1/datasets/test-pki/manifest")[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_collision_hooks_and_failed_rotation(live, monkeypatch):
    server, root, source = live
    identity, _ = probe(f"https://127.0.0.1:{server.server_address[1]}")
    target = root / "target"
    target.write_text("existing")
    marker = root / "hook-marker"
    hook = (
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
    )
    settings = DatasetConfig(target, hook, 2)
    client = Client(ClientConfig(root / "client", 1, {"shared-config": settings}))
    client.save_trust(identity)
    server.open(120)
    client.enroll("synthetic-client")
    server.close_window()
    old_key = client.credentials()[1].read_bytes()
    original_request = client.request

    def fail_rotate(method, path, payload=None, authenticated=True):
        if path == "/v1/rotate":
            raise ClientError("simulated outage")
        return original_request(method, path, payload, authenticated)

    monkeypatch.setattr(client, "request", fail_rotate)
    with pytest.raises(ClientError, match="simulated outage"):
        client.rotate()
    assert client.credentials()[1].read_bytes() == old_key
    monkeypatch.setattr(client, "request", original_request)
    with pytest.raises(ClientError, match="target collision"):
        client.sync()
    assert target.read_text() == "existing"
    assert not marker.exists()
    target.unlink()
    assert client.sync() == {"shared-config": True}
    assert marker.read_text() == "ran"
    marker.unlink()
    assert client.sync() == {"shared-config": False}
    assert not marker.exists()
    (source / "hello.txt").write_text("after")
    failing_hook = (sys.executable, "-c", "import sys; sys.exit(7)")
    with pytest.raises(ClientError, match="hook.*failed"):
        client.sync_one("shared-config", DatasetConfig(target, failing_hook, 2))
    assert (target / "hello.txt").read_text() == "after"


def test_reenrollment_after_identity_loss(live):
    server, root, _ = live
    identity, _ = probe(f"https://127.0.0.1:{server.server_address[1]}")
    client = Client(ClientConfig(root / "client"))
    client.save_trust(identity)
    server.open(20)
    old_id = client.enroll("synthetic-client")
    server.close_window()
    (client.state / "credentials/current").unlink()
    with pytest.raises(RegistrationClosed):
        client.enroll("synthetic-client")
    server.open(20)
    new_id = client.enroll("synthetic-client")
    assert new_id != old_id
    assert client.request("GET", "/v1/datasets")[0] == 200


def test_registration_expiry(live):
    server, _, _ = live
    server.open(1)
    assert server.remaining() > 0
    time.sleep(1.05)
    assert server.remaining() == 0


def test_csr_rejects_extensions_and_extra_subject(live):
    server, _, _ = live
    client_id = "00000000-0000-4000-8000-000000000001"
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)])
    bad_extensions = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False)
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(ValueError, match="CSR client ID mismatch"):
        sign_client_csr(server.config.state_dir, bad_extensions, client_id)
    bad_subject = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, client_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "synthetic"),
                ]
            )
        )
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(ValueError, match="CSR client ID mismatch"):
        sign_client_csr(server.config.state_dir, bad_subject, client_id)


def test_duplicate_public_key_cannot_enroll_twice(live):
    server, root, _ = live
    url = f"https://127.0.0.1:{server.server_address[1]}"
    client = Client(ClientConfig(root / "client"))
    client.save_trust(probe(url)[0])
    server.open(20)
    key = ed25519.Ed25519PrivateKey.generate()
    for index, expected in ((1, 200), (2, 409)):
        client_id = f"00000000-0000-4000-8000-{index:012d}"
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_id)]))
            .sign(key, None)
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
        status, _ = client.request(
            "POST",
            "/v1/enroll",
            {"client_id": client_id, "name": "synthetic", "csr": csr},
            authenticated=False,
        )
        assert status == expected


def test_local_control_socket_open_close_and_restart(tmp_path):
    try:
        check = socket.socket(socket.AF_UNIX)
    except PermissionError:
        pytest.skip("AF_UNIX sockets are unavailable in this sandbox")
    else:
        check.close()
    config = ServerConfig(
        state_dir=tmp_path / "server",
        runtime_dir=tmp_path / "run",
        source_root=tmp_path,
        host="127.0.0.1",
        port=0,
        discovery=False,
    )
    socket_path = config.runtime_dir / "server.sock"
    for restart in range(2):
        server = DistributionServer(config)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        try:
            assert control(socket_path, "status")["remaining"] == 0
            if restart == 0:
                assert "until" in control(socket_path, "open", 20)
                assert int(control(socket_path, "status")["remaining"]) > 0
                assert control(socket_path, "close")["closed"] is True
                assert control(socket_path, "status")["remaining"] == 0
                control(socket_path, "open", 20)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def test_reconnect_rejects_a_different_server(live):
    server, root, _ = live
    first = f"https://127.0.0.1:{server.server_address[1]}"
    client = Client(ClientConfig(root / "client"))
    client.save_trust(probe(first)[0])
    other_config = replace(
        server.config,
        state_dir=root / "other-server",
        runtime_dir=root / "other-run",
        port=0,
    )
    other = DistributionServer(other_config, control_enabled=False)
    thread = threading.Thread(target=other.start, daemon=True)
    thread.start()
    try:
        url = f"https://127.0.0.1:{other.server_address[1]}"
        with pytest.raises(ClientError, match="different server identity"):
            client.reconnect(url)
        assert client.trust()["url"] == first
    finally:
        other.shutdown()
        other.server_close()
        thread.join(timeout=3)


def test_ipv6_https_binding_when_available(tmp_path):
    config = ServerConfig(
        state_dir=tmp_path / "server",
        runtime_dir=tmp_path / "run",
        source_root=tmp_path,
        host="::1",
        port=0,
        discovery=False,
    )
    try:
        server = DistributionServer(config, control_enabled=False)
    except OSError as exc:
        pytest.skip(f"IPv6 loopback unavailable: {exc}")
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    try:
        identity, _ = probe(f"https://[::1]:{server.server_address[1]}")
        assert identity["server_id"] == server.server_id
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
