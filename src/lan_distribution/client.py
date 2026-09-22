"""Pinned TLS client, enrollment, rotation, and atomic local replicas."""

import datetime as dt
import fcntl
import grp
import hashlib
import json
import logging
import os
import random
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from http.client import HTTPSConnection
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from . import defaults
from .config import ClientConfig, DatasetConfig, name
from .crypto import new_client_key_csr, public_fingerprint, write_private
from .datasets import extract_verified, validate_manifest

LOG = logging.getLogger(__name__)


class ClientError(RuntimeError):
    pass


class RegistrationClosed(ClientError):
    pass


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _same_tree(left: Path, right: Path) -> bool:
    """Reuse an interrupted, complete version only when every entry matches."""
    for root, dirs, files in os.walk(left):
        relative = Path(root).relative_to(left)
        counterpart = right / relative
        if not counterpart.is_dir() or counterpart.is_symlink():
            return False
        if sorted(dirs + files) != sorted(p.name for p in counterpart.iterdir()):
            return False
        if (Path(root).stat().st_mode & 0o777) != (counterpart.stat().st_mode & 0o777):
            return False
        for filename in files:
            source, target = Path(root) / filename, counterpart / filename
            if target.is_symlink() or not target.is_file():
                return False
            if (source.stat().st_mode & 0o777) != (target.stat().st_mode & 0o777):
                return False
            if (
                hashlib.sha256(source.read_bytes()).digest()
                != hashlib.sha256(target.read_bytes()).digest()
            ):
                return False
    return True


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def probe(url: str) -> tuple[dict[str, str], str]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ClientError("server URL must be https://host:port")
    # Only the initial, interactive TOFU probe lacks a trust anchor. The
    # certificate fingerprint is shown before any identity is persisted.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=5, context=context)
    try:
        connection.connect()
        assert connection.sock is not None
        der = connection.sock.getpeercert(binary_form=True)
        if der is None:
            raise ClientError("server did not provide a certificate")
        cert = x509.load_der_x509_certificate(der)
        fingerprint = public_fingerprint(cert)
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        connection.request("GET", "/v1/identity")
        response = connection.getresponse()
        data = response.read(4096)
        if response.status != 200:
            raise ClientError("server identity endpoint failed")
        identity = json.loads(data)
        if identity.get("protocol") != defaults.PROTOCOL or not identity.get("server_id"):
            raise ClientError("unsupported server identity")
        return {
            "server_id": str(identity["server_id"]),
            "name": str(identity["name"]),
            "url": url,
            "fingerprint": fingerprint,
            "certificate": pem,
        }, fingerprint
    finally:
        connection.close()


class Client:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.state = config.state_dir
        if self.state.is_symlink():
            raise ClientError(f"state path is a symlink: {self.state}")
        if not self.state.exists():
            self.state.mkdir(parents=True, mode=0o711)
            self.state.chmod(0o711)

    @contextmanager
    def lock(self, name: str):
        """Serialize local credential and replica switches across CLI and daemon processes."""
        with (self.state / f".{name}.lock").open("a+b") as lockfile:
            fcntl.flock(lockfile, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lockfile, fcntl.LOCK_UN)

    def trust(self) -> dict[str, str]:
        try:
            return json.loads((self.state / "trust.json").read_text())
        except FileNotFoundError as exc:
            raise ClientError("not enrolled; run lan-distribution-client enroll") from exc

    def credentials(self) -> tuple[Path, Path] | None:
        current = self.state / "credentials" / "current"
        if not current.is_symlink():
            return None
        try:
            generation = current.resolve(strict=True)
        except FileNotFoundError:
            return None
        if generation.parent != current.parent or not generation.is_dir():
            raise ClientError("credential link points outside credential storage")
        for item in ("cert.pem", "key.pem"):
            if (generation / item).is_symlink() or not (generation / item).is_file():
                raise ClientError("credential file is missing or unsafe")
        return generation / "cert.pem", generation / "key.pem"

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[int, bytes]:
        trust = self.trust()
        if path != "/v1/identity":
            status, identity_body = self.request("GET", "/v1/identity", authenticated=authenticated)
            if status != 200 or json.loads(identity_body).get("server_id") != trust["server_id"]:
                raise ClientError("server ID changed")
        parsed = urlsplit(trust["url"])
        context = ssl.create_default_context(cadata=trust["certificate"])
        context.check_hostname = (
            False  # Exact certificate pin and server_id replace hostname binding.
        )
        if authenticated:
            credentials = self.credentials()
            if credentials is None:
                raise ClientError(
                    "client identity missing; re-enrollment requires registration window"
                )
            context.load_cert_chain(str(credentials[0]), str(credentials[1]))
        if parsed.hostname is None:
            raise ClientError("stored server URL is invalid")
        conn = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10, context=context)
        try:
            conn.connect()
            assert conn.sock is not None
            der = conn.sock.getpeercert(binary_form=True)
            if der is None:
                raise ClientError("server did not provide a certificate")
            cert = x509.load_der_x509_certificate(der)
            if public_fingerprint(cert) != trust["fingerprint"]:
                raise ClientError("server fingerprint changed")
            data = json.dumps(payload).encode() if payload is not None else None
            conn.request(
                method,
                path,
                body=data,
                headers={"Content-Type": "application/json"} if data else {},
            )
            response = conn.getresponse()
            length = response.getheader("Content-Length")
            if length is None or not length.isdecimal() or int(length) > defaults.MAX_BODY:
                raise ClientError("response exceeds size limit")
            body = response.read(int(length) + 1)
            if len(body) != int(length):
                raise ClientError("incomplete response")
            return response.status, body
        finally:
            conn.close()

    def save_trust(self, identity: dict[str, str]) -> None:
        if (self.state / "trust.json").exists():
            old = self.trust()
            if (
                old["server_id"] != identity["server_id"]
                or old["fingerprint"] != identity["fingerprint"]
            ):
                raise ClientError("already bound to a different server identity")
        # Installed state permits group members to run `status`; this is
        # public server-identity data, unlike the private key below.
        atomic_write(self.state / "trust.json", json.dumps(identity).encode(), 0o640)

    def reconnect(self, url: str) -> None:
        old = self.trust()
        identity, _ = probe(url)
        if (
            identity["server_id"] != old["server_id"]
            or identity["fingerprint"] != old["fingerprint"]
        ):
            raise ClientError("new URL has a different server identity")
        self.save_trust(identity)

    def _install_credentials(self, key: bytes, cert: bytes, ca_cert: bytes, client_id: str) -> None:
        private = serialization.load_pem_private_key(key, None)
        certificate = x509.load_pem_x509_certificate(cert)
        ca = x509.load_pem_x509_certificate(ca_cert)
        certificate.verify_directly_issued_by(ca)
        if certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value != client_id or certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ClientError("signed certificate does not match local identity")
        root = self.state / "credentials"
        root.mkdir(exist_ok=True, mode=0o2710)
        root.chmod(0o2710)
        generation = root / str(uuid.uuid4())
        generation.mkdir(mode=0o2710)
        write_private(generation / "key.pem", key)
        atomic_write(generation / "cert.pem", cert + ca_cert)
        atomic_write(generation / "client-id", client_id.encode())
        directory_fd = os.open(generation, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        current = root / "current"
        temp = root / (".current-" + uuid.uuid4().hex)
        temp.symlink_to(generation.name)
        os.replace(temp, current)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        old_generations = sorted(
            (
                child
                for child in root.iterdir()
                if child.is_dir() and not child.is_symlink() and child != generation
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for child in old_generations[1:]:
            shutil.rmtree(child)

    def enroll(self, client_name: str) -> str:
        if self.credentials() is not None:
            raise ClientError("client is already enrolled")
        client_id = str(uuid.uuid4())
        key, csr = new_client_key_csr(client_id)
        status, body = self.request(
            "POST",
            "/v1/enroll",
            {"client_id": client_id, "name": client_name, "csr": csr.decode()},
            authenticated=False,
        )
        if status == 403 and json.loads(body).get("error") == "registration closed":
            raise RegistrationClosed("server registration is closed")
        if status != 200:
            raise ClientError(f"enrollment failed: {body.decode(errors='replace')}")
        result = json.loads(body)
        if result["client_id"] != client_id:
            raise ClientError("server returned wrong client ID")
        self._install_credentials(
            key, result["certificate"].encode(), result["ca_certificate"].encode(), client_id
        )
        atomic_write(self.state / "client-id", client_id.encode())
        return client_id

    def rotate(self) -> None:
        with self.lock("credentials"):
            self._rotate_locked()

    def _rotate_locked(self) -> None:
        credentials = self.credentials()
        if credentials is None:
            raise ClientError("client identity missing; re-enrollment required")
        client_id = (credentials[0].parent / "client-id").read_text().strip()
        key, csr = new_client_key_csr(client_id)
        status, body = self.request("POST", "/v1/rotate", {"csr": csr.decode()})
        if status != 200:
            raise ClientError(f"rotation failed: {body.decode(errors='replace')}")
        result = json.loads(body)
        if result["client_id"] != client_id:
            raise ClientError("rotation returned wrong client ID")
        self._install_credentials(
            key, result["certificate"].encode(), result["ca_certificate"].encode(), client_id
        )

    def rotate_if_due(self) -> bool:
        credentials = self.credentials()
        if credentials is None:
            raise ClientError("client identity missing")
        cert = x509.load_pem_x509_certificate(credentials[0].read_bytes())
        if cert.not_valid_after_utc - dt.datetime.now(dt.UTC) <= dt.timedelta(days=7):
            self.rotate()
            return True
        return False

    def sync_one(self, dataset: str, settings: DatasetConfig) -> bool:
        with self.lock(f"dataset-{name(dataset)}"):
            return self._sync_one_locked(dataset, settings)

    def _sync_one_locked(self, dataset: str, settings: DatasetConfig) -> bool:
        name(dataset)
        base = self.state / "datasets" / dataset
        versions = base / "versions"
        managed = base / ".managed"
        current = base / "current"
        for directory in (self.state / "datasets", base, versions, managed):
            if directory.is_symlink():
                raise ClientError(f"replica path is a symlink: {directory}")
        if current.is_symlink() and not re.fullmatch(
            r"versions/[0-9a-f]{64}", current.readlink().as_posix()
        ):
            raise ClientError(f"current link points outside versions: {current}")
        if settings.target is not None and (
            settings.target.exists() or settings.target.is_symlink()
        ):
            if not settings.target.is_symlink() or settings.target.readlink() != current:
                raise ClientError(f"target collision: {settings.target}")

        def ensure_target() -> None:
            if settings.target is None:
                return
            if settings.target.is_symlink():
                if settings.target.readlink() != current:
                    raise ClientError(f"target collision: {settings.target}")
            elif settings.target.exists():
                raise ClientError(f"target collision: {settings.target}")
            else:
                settings.target.parent.mkdir(parents=True, exist_ok=True)
                settings.target.symlink_to(current)

        status, body = self.request("GET", f"/v1/datasets/{dataset}/manifest")
        if status != 200:
            raise ClientError(f"cannot read {dataset} manifest: HTTP {status}")
        manifest = json.loads(body)
        validate_manifest(manifest)
        version = manifest["version"]
        if (
            current.is_symlink()
            and current.readlink() == Path("versions") / version
            and (versions / version).is_dir()
            and not (versions / version).is_symlink()
        ):
            ensure_target()
            return False
        status, archive = self.request("GET", f"/v1/datasets/{dataset}/archive")
        if status != 200:
            raise ClientError(f"cannot read {dataset} archive: HTTP {status}")
        datasets_root = self.state / "datasets"
        datasets_root.mkdir(parents=True, exist_ok=True, mode=0o711)
        datasets_root.chmod(0o711)
        base.mkdir(parents=True, exist_ok=True, mode=0o711)
        base.chmod(0o711)
        versions.mkdir(parents=True, exist_ok=True, mode=0o711)
        versions.chmod(0o711)
        managed.mkdir(parents=True, exist_ok=True, mode=0o700)
        managed.chmod(0o700)
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=versions))
        try:
            extract_verified(archive, manifest, stage)
            stage.chmod(0o711)
            if settings.group:
                try:
                    group_id = grp.getgrnam(settings.group).gr_gid
                except KeyError as exc:
                    raise ClientError(f"local group does not exist: {settings.group}") from exc
                for root, directories, files in os.walk(stage):
                    os.chown(root, -1, group_id)
                    for item in directories + files:
                        os.chown(Path(root) / item, -1, group_id)
            _fsync_directory(stage)
            final = versions / version
            if final.exists() or final.is_symlink():
                if not final.is_dir() or final.is_symlink() or not _same_tree(stage, final):
                    raise ClientError(f"version path collision: {final}")
            else:
                os.replace(stage, final)
            atomic_write(managed / version, b"managed\n")
            directory_fd = os.open(versions, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            temp_link = base / (".current-" + uuid.uuid4().hex)
            temp_link.symlink_to(Path("versions") / version)
            if (current.exists() or current.is_symlink()) and not current.is_symlink():
                temp_link.unlink()
                raise ClientError(f"current path collision: {current}")
            os.replace(temp_link, current)
            directory_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            ensure_target()
            keep = sorted(
                (
                    p
                    for p in versions.iterdir()
                    if p.is_dir()
                    and not p.is_symlink()
                    and re.fullmatch(r"[0-9a-f]{64}", p.name)
                    and (managed / p.name).is_file()
                    and not (managed / p.name).is_symlink()
                ),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in keep[settings.retain :]:
                if old != final and current.readlink() != Path("versions") / old.name:
                    shutil.rmtree(old)
                    (managed / old.name).unlink(missing_ok=True)
            if settings.post_update:
                try:
                    result = subprocess.run(
                        settings.post_update,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    LOG.error("hook %s timed out after %s seconds", dataset, exc.timeout)
                    raise ClientError(f"post-update hook for {dataset} timed out") from exc
                LOG.info(
                    "hook %s exit=%s stdout=%s stderr=%s",
                    dataset,
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
                if result.returncode:
                    raise ClientError(
                        f"post-update hook for {dataset} failed with exit {result.returncode}"
                    )
            return True
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def sync(self) -> dict[str, bool]:
        status, body = self.request("GET", "/v1/datasets")
        if status != 200:
            raise ClientError(f"cannot list datasets: HTTP {status}")
        allowed = set(json.loads(body)["datasets"])
        results = {}
        for dataset in self.config.datasets:
            if dataset not in allowed:
                raise ClientError(f"dataset not authorized: {dataset}")
            results[dataset] = self.sync_one(dataset, self.config.datasets[dataset])
        return results

    def run(self) -> None:
        while True:
            try:
                self.rotate_if_due()
                self.sync()
            except Exception:
                LOG.exception("client cycle failed; existing replicas remain available")
            time.sleep(self.config.interval_seconds * random.uniform(0.9, 1.1))
