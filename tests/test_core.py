import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest
from zeroconf import ServiceInfo

from lan_distribution import cli, defaults, discovery
from lan_distribution.cli import choose, duration
from lan_distribution.client import Client, ClientError, RegistrationClosed, probe
from lan_distribution.config import (
    ClientConfig,
    ConfigError,
    DatasetConfig,
    load_client,
    load_server,
)
from lan_distribution.datasets import (
    current_published,
    extract_verified,
    publish,
    safe_path,
    snapshot,
    validate_manifest,
)
from lan_distribution.discovery import FoundServer


@pytest.mark.parametrize(
    "value,seconds", [("20sec", 20), ("2min", 120), ("15min", 900), ("1h", 3600)]
)
def test_duration(value, seconds):
    assert duration(value) == seconds


@pytest.mark.parametrize("value", ["0sec", "2minutes", "x", "999h"])
def test_bad_duration(value):
    with pytest.raises(argparse.ArgumentTypeError):
        duration(value)


def test_discovery_selection():
    servers = [
        FoundServer("a", "192.0.2.1", 9443, "id-a"),
        FoundServer("b", "192.0.2.2", 9443, "id-b"),
    ]
    assert choose(servers, "2").server_id == "id-b"
    assert choose(servers, "m") is None
    with pytest.raises(ValueError):
        choose([], "1")
    with pytest.raises(ValueError):
        choose(servers, "3")


def test_mdns_service_type_is_accepted_by_zeroconf():
    service = ServiceInfo(
        defaults.SERVICE_TYPE,
        f"regression.{defaults.SERVICE_TYPE}",
        addresses=[b"\xc0\x00\x02\x0a"],
        port=9443,
    )

    assert service.type == defaults.SERVICE_TYPE


def test_discovery_interactive_paths(monkeypatch):
    server = FoundServer("lab", "192.0.2.10", 9443, "stable-id")
    monkeypatch.setattr(cli, "discover", lambda: [])
    monkeypatch.setattr("builtins.input", lambda _: "f")
    assert cli.select_server() == ("", None)
    answers = iter(["m", "https://192.0.2.20:9443"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.select_server() == ("https://192.0.2.20:9443", None)
    monkeypatch.setattr(cli, "discover", lambda: [server])
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert cli.select_server() == (server.url, "stable-id")
    other = FoundServer("other", "192.0.2.11", 9443, "other-id")
    monkeypatch.setattr(cli, "discover", lambda: [server, other])
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert cli.select_server() == (other.url, "other-id")


def test_discovery_filters_stale_malformed_and_duplicate_announcements(monkeypatch):
    stable = "00000000-0000-4000-8000-000000000001"
    other = "00000000-0000-4000-8000-000000000002"

    class Info:
        def __init__(self, server_id, addresses):
            self.properties = {b"protocol": b"1", b"server_id": server_id}
            self.port = 9443
            self._addresses = addresses

        def parsed_addresses(self):
            return self._addresses

    records = {
        "live._landist._tcp.local.": Info(stable.encode(), ["2001:db8::10", "192.0.2.10"]),
        "duplicate._landist._tcp.local.": Info(stable.encode(), ["192.0.2.10"]),
        "other._landist._tcp.local.": Info(other.encode(), ["2001:db8::20"]),
        "bad._landist._tcp.local.": Info(b"not-a-uuid", ["192.0.2.30"]),
        "stale._landist._tcp.local.": Info(other.encode(), ["192.0.2.40"]),
    }

    class FakeZeroconf:
        def get_service_info(self, service_type, service_name):
            return records[service_name]

        def close(self):
            pass

    class FakeBrowser:
        def __init__(self, zeroconf, service_type, listener):
            for service_name in records:
                listener.add_service(zeroconf, service_type, service_name)
            listener.remove_service(zeroconf, service_type, "stale._landist._tcp.local.")

        def cancel(self):
            pass

    monkeypatch.setattr(discovery, "Zeroconf", FakeZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", FakeBrowser)
    monkeypatch.setattr(discovery.time, "sleep", lambda _: None)
    found = discovery.discover(0)
    assert len(found) == 2
    assert found[0].address == "192.0.2.10"
    assert found[-1].url == "https://[2001:db8::20]:9443"


def test_trust_requires_explicit_yes_and_closed_retry_only_enroll(tmp_path, monkeypatch):
    config = tmp_path / "client.toml"
    config.write_text(f'[client]\nstate_dir="{tmp_path / "state"}"\n')
    identity = {
        "server_id": "00000000-0000-4000-8000-000000000001",
        "name": "synthetic",
        "url": "https://192.0.2.10:9443",
        "fingerprint": "SHA256:synthetic",
        "certificate": "synthetic",
    }
    calls = {"probe": 0, "enroll": 0}

    def fake_probe(url):
        calls["probe"] += 1
        return identity, identity["fingerprint"]

    monkeypatch.setattr(cli, "probe", fake_probe)
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert cli.enroll_interactive(config, identity["url"]) == 0
    assert not (tmp_path / "state/trust.json").exists()

    class FakeClient:
        def __init__(self, config):
            self.state = tmp_path / "state"

        def credentials(self):
            return None

        def save_trust(self, selected):
            assert selected == identity

        def enroll(self, client_name):
            calls["enroll"] += 1
            if calls["enroll"] == 1:
                raise RegistrationClosed("closed")
            return "synthetic-client-id"

    monkeypatch.setattr(cli, "Client", FakeClient)
    answers = iter(["yes", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.enroll_interactive(config, identity["url"]) == 0
    assert calls == {"probe": 2, "enroll": 2}


@pytest.mark.parametrize(
    "url", ["http://example.test", "https://example.test/?x=1", "https://example.test/#x"]
)
def test_probe_rejects_unsafe_manual_url(url):
    with pytest.raises(ClientError, match="server URL"):
        probe(url)


def test_advertising_only_announces_bound_address_family(monkeypatch):
    class IP:
        def __init__(self, value):
            self.ip = value

    class Adapter:
        ips = [IP("192.0.2.10"), IP(("2001:db8::10", 0, 0)), IP("127.0.0.1")]

    class FakeZeroconf:
        def register_service(self, service, allow_name_change):
            pass

    class FakeServiceInfo:
        def __init__(self, *args, **kwargs):
            self.addresses = kwargs["addresses"]
            self.properties = kwargs["properties"]

    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: [Adapter()])
    monkeypatch.setattr(discovery, "Zeroconf", FakeZeroconf)
    monkeypatch.setattr(discovery, "ServiceInfo", FakeServiceInfo)
    server_id = "00000000-0000-4000-8000-000000000001"
    _, ipv4 = discovery.advertise("synthetic", 9443, server_id)
    _, ipv6 = discovery.advertise("synthetic", 9443, server_id, "::")
    assert len(ipv4.addresses[0]) == 4
    assert len(ipv6.addresses[0]) == 16
    assert ipv4.properties["server_id"] == server_id
    assert ipv4.properties["name"] == "synthetic"


def test_admin_open_cli(monkeypatch, capsys):
    seen = []

    def fake_control(path, action, seconds):
        seen.append((action, seconds))
        return {"until": "2026-01-01T12:02:00"}

    monkeypatch.setattr(cli, "control", fake_control)
    monkeypatch.setattr(sys, "argv", ["lan-distribution", "open", "2min"])
    assert cli.main() == 0
    assert seen == [("open", 120)]
    assert "Client registration enabled for 2 minutes" in capsys.readouterr().out


def test_config(tmp_path):
    server = tmp_path / "server.toml"
    server.write_text(
        '[server]\nsource_root="/srv/lan-distribution"\n[datasets]\nshared="/srv/lan-distribution/shared"\n'
    )
    assert load_server(server).datasets["shared"] == Path("/srv/lan-distribution/shared")
    server.write_text(
        '[server]\nsource_root="/srv/lan-distribution"\n[datasets]\n'
        'shared="/srv/lan-distribution/shared"\n[datasets.test-pki]\npublished=true\n'
    )
    assert load_server(server).datasets == {
        "shared": Path("/srv/lan-distribution/shared"),
        "test-pki": None,
    }
    client = tmp_path / "client.toml"
    client.write_text(
        '[client]\ninterval_seconds=12\n[datasets.shared]\npost_update=["true"]\ngroup="example-service"\n'
    )
    assert load_client(client).datasets["shared"].post_update == ("true",)
    assert load_client(client).datasets["shared"].group == "example-service"
    client.write_text("[client]\ninterval_seconds=0\n")
    with pytest.raises(ConfigError):
        load_client(client)
    client.write_text("[client\n")
    with pytest.raises(ConfigError):
        load_client(client)
    server.write_text('[datasets]\nbad="/tmp/other"\n')
    with pytest.raises(ConfigError):
        load_server(server)
    server.write_text("[server]\nsource_root=42\n")
    with pytest.raises(ConfigError, match="source_root"):
        load_server(server)
    client.write_text('[datasets.shared]\ntarget="relative/path"\n')
    with pytest.raises(ConfigError, match="absolute"):
        load_client(client)


def test_shipped_zero_config_defaults():
    root = Path(__file__).resolve().parents[1]
    server = load_server(root / "config/server.toml")
    client = load_client(root / "config/client.toml")
    assert server.discovery is True
    assert server.port == 9443
    assert server.datasets["shared-config"] == Path("/srv/lan-distribution/shared-config")
    assert server.state_dir == Path("/var/lib/lan-distribution/server")
    assert client.datasets["shared-config"].target == Path("/etc/lan-distribution/shared-config")


def test_snapshot_and_archive_safety(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("content")
    manifest, archive = snapshot(source)
    assert manifest["version"] == snapshot(source)[0]["version"]
    output = tmp_path / "out"
    output.mkdir()
    extract_verified(archive, manifest, output)
    assert (output / "file").read_text() == "content"
    assert (output / "file").stat().st_mode & 0o777 == (source / "file").stat().st_mode & 0o777
    with pytest.raises(ValueError, match="checksum"):
        extract_verified(archive.replace(b"content", b"corrupt"), manifest, tmp_path / "tampered")
    with pytest.raises(ValueError, match="size limit"):
        snapshot(source, limit=1)
    (source / "link").symlink_to("file")
    with pytest.raises(ValueError):
        snapshot(source)
    (source / "link").unlink()
    os.link(source / "file", source / "hardlink")
    with pytest.raises(ValueError, match="hard link"):
        snapshot(source)
    (source / "hardlink").unlink()
    for path in ("../bad", "/absolute", "a/../b", "a//b"):
        with pytest.raises(ValueError):
            safe_path(path)
    altered = dict(manifest)
    altered["version"] = "0" * 64
    with pytest.raises(ValueError):
        validate_manifest(altered)
    bad = io.BytesIO()
    with tarfile.open(fileobj=bad, mode="w") as tar:
        info = tarfile.TarInfo("../bad")
        tar.addfile(info, io.BytesIO())
    with pytest.raises(ValueError):
        extract_verified(bad.getvalue(), manifest, tmp_path / "bad")


def test_atomic_published_dataset_store(tmp_path, monkeypatch):
    state = tmp_path / "server-state"
    source = tmp_path / "source"
    source.mkdir()
    secret = source / "key.pem"
    secret.write_text("first-key")
    secret.chmod(0o600)
    (source / "cert.pem").write_text("first-cert")

    first, changed = publish(state, "test-pki", source)
    assert changed
    root = state / "datasets/test-pki"
    assert root.joinpath("current").readlink() == Path("versions") / first
    old = current_published(state, "test-pki")
    assert old is not None
    assert (old / "key.pem").read_text() == "first-key"
    assert (old / "key.pem").stat().st_mode & 0o777 == 0o600
    assert publish(state, "test-pki", source) == (first, False)
    assert len(list((root / "versions").iterdir())) == 1

    secret.write_text("second-key")
    second, changed = publish(state, "test-pki", source)
    assert changed and second != first
    assert root.joinpath("current").readlink() == Path("versions") / second
    assert (root / "versions" / first / "key.pem").read_text() == "first-key"
    assert (root / "versions" / second / "key.pem").read_text() == "second-key"
    secret.chmod(0o640)
    third, changed = publish(state, "test-pki", source)
    assert changed and third != second

    def fail_extract(*args, **kwargs):
        raise OSError("synthetic staging failure")

    secret.write_text("failed-key")
    monkeypatch.setattr("lan_distribution.datasets.extract_verified", fail_extract)
    with pytest.raises(OSError, match="staging failure"):
        publish(state, "test-pki", source)
    assert root.joinpath("current").readlink() == Path("versions") / third
    assert not list((root / "versions").glob(".stage-*"))

    with pytest.raises(ValueError, match="dataset name"):
        publish(state, "../escape", source)
    fifo = source / "fifo"
    os.mkfifo(fifo)
    try:
        with pytest.raises(ValueError, match="unsupported"):
            publish(state, "test-pki", source)
    finally:
        fifo.unlink()


def test_dataset_permission_modes_and_version_identity(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    private = source / "private"
    private.mkdir()
    public = source / "public"
    public.mkdir()
    files = {
        source / "plain.txt": ("plain", 0o644),
        source / "secret.txt": ("secret", 0o600),
        source / "run": ("#!/bin/sh\n", 0o755),
        private / "key.pem": ("key", 0o600),
        public / "certificate.pem": ("cert", 0o644),
    }
    for path, (content, mode) in files.items():
        path.write_text(content)
        path.chmod(mode)
    private.chmod(0o700)
    public.chmod(0o755)

    manifest, archive = snapshot(source)
    modes = {entry["path"]: entry["mode"] for entry in manifest["entries"]}
    assert modes == {
        "plain.txt": 0o644,
        "private": 0o700,
        "private/key.pem": 0o600,
        "public": 0o755,
        "public/certificate.pem": 0o644,
        "run": 0o755,
        "secret.txt": 0o600,
    }
    original_version = manifest["version"]
    (source / "plain.txt").chmod(0o600)
    assert snapshot(source)[0]["version"] != original_version
    (source / "plain.txt").chmod(0o644)

    # Special source bits are intentionally absent from both manifest and output.
    (source / "run").chmod(0o7755)
    special_manifest, special_archive = snapshot(source)
    assert (
        next(entry for entry in special_manifest["entries"] if entry["path"] == "run")["mode"]
        == 0o755
    )
    special_output = tmp_path / "special-output"
    extract_verified(special_archive, special_manifest, special_output)
    assert (special_output / "run").stat().st_mode & 0o7000 == 0
    (source / "run").chmod(0o755)

    observed_file_modes: list[int] = []
    real_fchmod = os.fchmod

    def observe_initial_mode(fd, mode):
        current = os.fstat(fd).st_mode
        if stat.S_ISREG(current):
            observed_file_modes.append(stat.S_IMODE(current))
        real_fchmod(fd, mode)

    monkeypatch.setattr("lan_distribution.datasets.os.fchmod", observe_initial_mode)
    output = tmp_path / "output"
    output.mkdir()
    old_umask = os.umask(0o000)
    try:
        extract_verified(archive, manifest, output)
    finally:
        os.umask(old_umask)
    for path, (_, mode) in files.items():
        relative = path.relative_to(source)
        assert (output / relative).stat().st_mode & 0o777 == mode
    assert (output / "private").stat().st_mode & 0o777 == 0o700
    assert (output / "public").stat().st_mode & 0o777 == 0o755
    assert observed_file_modes == [0o000] * len(files)
    assert (output / "run").stat().st_mode & 0o7000 == 0

    invalid = json.loads(json.dumps(manifest))
    invalid["entries"][0]["mode"] = 0o1000
    invalid["version"] = hashlib.sha256(
        json.dumps(invalid["entries"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="invalid mode"):
        validate_manifest(invalid)


def test_install_targets_and_preservation():
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text()
    assert "install: install-client" in makefile
    assert "install-client:\n\t./scripts/install.sh client" in makefile
    assert "install-server:\n\t./scripts/install.sh server" in makefile
    assert "uninstall:\n\t./scripts/uninstall.sh" in makefile
    installer = (root / "scripts/install.sh").read_text()
    assert 'if [[ "$role" == server ]]' in installer
    assert 'copy_default "$repo_dir/config/server.toml" "$config_dir/server.toml"' in installer
    assert 'copy_default "$repo_dir/config/client.toml" "$config_dir/client.toml"' in installer
    assert '[[ ! -e "$target" && ! -L "$target" ]]' in installer
    assert "systemctl enable --now lan-distribution-server.service" in installer
    assert "systemctl enable --now lan-distribution-client.service" in installer
    uninstaller = (root / "scripts/uninstall.sh").read_text()
    assert "for role in client server" in uninstaller
    assert "if ! installed client && ! installed server" in uninstaller
    assert "/var/lib/lan-distribution" not in uninstaller
    assert "/srv/lan-distribution" not in uninstaller


def test_replica_modes_with_systemd_umask(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("synthetic")
    (source / "file").chmod(0o600)
    (source / "private").mkdir()
    (source / "private").chmod(0o700)
    manifest, archive = snapshot(source)
    target = tmp_path / "target"
    old = os.umask(0o077)
    try:
        client = Client(ClientConfig(tmp_path / "client"))

        def fake_request(method, path):
            if path.endswith("manifest"):
                return 200, json.dumps(manifest).encode()
            return 200, archive

        monkeypatch.setattr(client, "request", fake_request)
        assert client.sync_one("shared", DatasetConfig(target))
    finally:
        os.umask(old)
    for path in (
        client.state,
        client.state / "datasets",
        client.state / "datasets/shared",
        client.state / "datasets/shared/versions",
    ):
        assert path.stat().st_mode & 0o777 == 0o711
    assert (target / "file").stat().st_mode & 0o777 == 0o600
    assert (target / "private").stat().st_mode & 0o777 == 0o700


def test_atomic_update_preserves_changed_modes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    file = source / "file"
    file.write_text("same bytes")
    file.chmod(0o644)
    client = Client(ClientConfig(tmp_path / "client"))
    target = tmp_path / "target"

    def fake_request(method, path):
        manifest, archive = snapshot(source)
        return 200, json.dumps(manifest).encode() if path.endswith("manifest") else archive

    monkeypatch.setattr(client, "request", fake_request)
    assert client.sync_one("shared", DatasetConfig(target))
    first = (client.state / "datasets/shared/current").readlink()
    assert (target / "file").stat().st_mode & 0o777 == 0o644
    file.chmod(0o600)
    assert client.sync_one("shared", DatasetConfig(target))
    assert (target / "file").stat().st_mode & 0o777 == 0o600
    assert (client.state / "datasets/shared/current").readlink() != first


def test_version_collision_and_interrupted_activation(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("good")
    manifest, archive = snapshot(source)
    client = Client(ClientConfig(tmp_path / "client"))
    target = tmp_path / "target"
    monkeypatch.setattr(
        client,
        "request",
        lambda method, path: (
            200,
            json.dumps(manifest).encode() if path.endswith("manifest") else archive,
        ),
    )
    final = client.state / "datasets/shared/versions" / manifest["version"]
    final.mkdir(parents=True)
    (final / "unrelated").write_text("keep")
    with pytest.raises(ClientError, match="version path collision"):
        client.sync_one("shared", DatasetConfig(target))
    assert (final / "unrelated").read_text() == "keep"
    (final / "unrelated").unlink()
    extract_verified(archive, manifest, final)
    final.chmod(0o711)
    assert client.sync_one("shared", DatasetConfig(target))
    assert (target / "file").read_text() == "good"
    assert client.sync_one("shared", DatasetConfig(target)) is False


def test_current_link_escape_rejected(tmp_path):
    client = Client(ClientConfig(tmp_path / "client"))
    base = client.state / "datasets/shared"
    base.mkdir(parents=True)
    (base / "current").symlink_to(tmp_path)
    with pytest.raises(ClientError, match="outside versions"):
        client.sync_one("shared", DatasetConfig())
    assert (base / "current").is_symlink()


def test_extract_rejects_existing_destination_and_oversize(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("good")
    manifest, archive = snapshot(source)
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep").write_text("synthetic")
    with pytest.raises(ValueError, match="empty"):
        extract_verified(archive, manifest, output)
    assert (output / "keep").read_text() == "synthetic"
