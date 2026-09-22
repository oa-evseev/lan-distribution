"""HTTPS server, ephemeral enrollment window, and server-side authorization."""

import datetime as dt
import json
import logging
import os
import re
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from . import defaults
from .config import ServerConfig, name
from .crypto import generate_server, sign_client_csr
from .datasets import current_published, published_root, snapshot

LOG = logging.getLogger(__name__)


def initialize(config: ServerConfig) -> str:
    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (config.state_dir / "server-id").exists():
        server_id = (config.state_dir / "server-id").read_text().strip()
        try:
            uuid.UUID(server_id)
        except ValueError as exc:
            raise ValueError("server state has an invalid identity") from exc
        required = ("tls-key.pem", "tls-cert.pem", "client-ca-key.pem", "client-ca-cert.pem")
        if any(not (config.state_dir / item).is_file() for item in required):
            raise ValueError("server state is incomplete; refusing to replace identity")
    else:
        server_id = generate_server(config.state_dir)
    with sqlite3.connect(config.state_dir / "server.db") as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, serial TEXT NOT NULL,
                certificate TEXT NOT NULL,
                previous_serial TEXT,
                status TEXT NOT NULL CHECK(status IN ('enabled','disabled','revoked'))
            );
            CREATE TABLE IF NOT EXISTS grants (
                client_id TEXT NOT NULL, dataset TEXT NOT NULL,
                PRIMARY KEY(client_id,dataset), FOREIGN KEY(client_id) REFERENCES clients(id)
            );
            CREATE TABLE IF NOT EXISTS client_keys (
                public_key TEXT PRIMARY KEY, client_id TEXT NOT NULL
            );
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(clients)")}
        if "public_key" not in columns:
            db.execute("ALTER TABLE clients ADD COLUMN public_key TEXT")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS clients_public_key ON clients(public_key)")
        db.execute(
            "INSERT OR IGNORE INTO client_keys SELECT public_key,id FROM clients WHERE public_key IS NOT NULL"
        )
    (config.state_dir / "server.db").chmod(0o600)
    return server_id


class DistributionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: ServerConfig, control_enabled: bool = True):
        self.config = config
        self.server_id = initialize(config)
        self.registration_until = 0.0
        self.window_lock = threading.Lock()
        self.address_family = socket.AF_INET6 if ":" in config.host else socket.AF_INET
        super().__init__((config.host, config.port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            str(config.state_dir / "tls-cert.pem"), str(config.state_dir / "tls-key.pem")
        )
        context.load_verify_locations(cafile=str(config.state_dir / "client-ca-cert.pem"))
        context.verify_mode = ssl.CERT_OPTIONAL
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.control = (
            ControlServer(str(config.runtime_dir / "server.sock"), self)
            if control_enabled
            else None
        )
        self.control_thread = (
            threading.Thread(target=self.control.serve_forever, daemon=True)
            if self.control is not None
            else None
        )

    def start(self) -> None:
        if self.control_thread is not None:
            self.control_thread.start()
        self.serve_forever(poll_interval=0.2)

    def server_close(self) -> None:
        if self.control is not None:
            if self.control_thread is not None and self.control_thread.is_alive():
                self.control.shutdown()
            self.control.server_close()
        super().server_close()

    def db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.config.state_dir / "server.db")

    def open(self, seconds: int) -> float:
        with self.window_lock:
            self.registration_until = time.monotonic() + seconds
        return time.time() + seconds

    def close_window(self) -> None:
        with self.window_lock:
            self.registration_until = 0

    def remaining(self) -> int:
        with self.window_lock:
            return max(0, int(self.registration_until - time.monotonic() + 0.999))


class Handler(BaseHTTPRequestHandler):
    server: DistributionServer

    def setup(self) -> None:
        self.request.settimeout(10)
        super().setup()

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("%s %s", self.address_string(), fmt % args)

    def reply(self, code: int, value: object) -> None:
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self) -> dict[str, object]:
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or int(length) > 16384:
            raise ValueError("invalid request size")
        value = json.loads(self.rfile.read(int(length)))
        if not isinstance(value, dict):
            raise ValueError("request must be an object")
        return value

    def client_id(self) -> str | None:
        cert_der = self.connection.getpeercert(binary_form=True)
        if not cert_der:
            return None
        cert = x509.load_der_x509_certificate(cert_der)
        serial = str(cert.serial_number)
        with self.server.db() as db:
            row = db.execute(
                "SELECT id FROM clients WHERE (serial=? OR previous_serial=?) AND status='enabled'",
                (serial, serial),
            ).fetchone()
        if row and cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(NameOID.COMMON_NAME, str(row[0]))
        ]:
            return str(row[0])
        return None

    def authorized(self, dataset: str) -> bool:
        client = self.client_id()
        if not client:
            return False
        with self.server.db() as db:
            return (
                db.execute(
                    "SELECT 1 FROM grants WHERE client_id=? AND dataset=?", (client, dataset)
                ).fetchone()
                is not None
            )

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/v1/identity":
            self.reply(
                200,
                {
                    "protocol": defaults.PROTOCOL,
                    "server_id": self.server.server_id,
                    "name": self.server.config.instance_name,
                },
            )
            return
        client = self.client_id()
        if client is None:
            self.reply(403, {"error": "client not authorized"})
            return
        if path == "/v1/datasets":
            with self.server.db() as db:
                rows = db.execute(
                    "SELECT dataset FROM grants WHERE client_id=?", (client,)
                ).fetchall()
            self.reply(
                200,
                {
                    "datasets": sorted(
                        row[0] for row in rows if row[0] in self.server.config.datasets
                    )
                },
            )
            return
        parts = path.split("/")
        if len(parts) not in (5, 6) or parts[1:3] != ["v1", "datasets"]:
            self.reply(404, {"error": "not found"})
            return
        dataset = unquote(parts[3])
        resource = parts[4]
        requested_version = parts[5] if len(parts) == 6 else None
        if resource not in ("manifest", "archive") or (
            requested_version is not None and resource != "archive"
        ):
            self.reply(404, {"error": "not found"})
            return
        try:
            name(dataset)
        except ValueError:
            self.reply(400, {"error": "invalid dataset name"})
            return
        if dataset not in self.server.config.datasets or not self.authorized(dataset):
            self.reply(403, {"error": "dataset not authorized"})
            return
        try:
            source = self.server.config.datasets[dataset]
            if source is None:
                if resource == "manifest":
                    source = current_published(self.server.config.state_dir, dataset)
                    if source is None:
                        raise ValueError("dataset has not been published")
                else:
                    if requested_version is None or not re.fullmatch(
                        r"[0-9a-f]{64}", requested_version
                    ):
                        raise ValueError("published archive request requires a version")
                    root = published_root(self.server.config.state_dir, dataset)
                    source = root / "versions" / requested_version
                    if not source.is_dir() or source.is_symlink():
                        raise ValueError("published version is unavailable")
            manifest, archive = snapshot(source, self.server.config.max_dataset_bytes)
            if requested_version is not None and manifest["version"] != requested_version:
                raise ValueError("published version does not match its identity")
        except (OSError, ValueError) as exc:
            LOG.warning("cannot snapshot %s: %s", dataset, exc)
            self.reply(503, {"error": "dataset unavailable"})
            return
        if resource == "manifest":
            self.reply(200, manifest)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-tar")
            self.send_header("Content-Length", str(len(archive)))
            self.end_headers()
            self.wfile.write(archive)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/v1/enroll", "/v1/rotate"):
            self.reply(404, {"error": "not found"})
            return
        try:
            body = self.body()
            csr = str(body["csr"]).encode()
            if path == "/v1/enroll":
                if self.server.remaining() == 0:
                    self.reply(403, {"error": "registration closed"})
                    return
                client_id = str(uuid.UUID(str(body["client_id"])))
                client_name = str(body.get("name", "client"))[:128]
                cert = sign_client_csr(self.server.config.state_dir, csr, client_id)
                issued = x509.load_pem_x509_certificate(cert)
                serial = str(issued.serial_number)
                public_key = (
                    issued.public_key()
                    .public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    .hex()
                )
                with self.server.db() as db:
                    db.execute("INSERT INTO client_keys VALUES (?,?)", (public_key, client_id))
                    db.execute(
                        "INSERT INTO clients (id,name,serial,certificate,status,public_key) VALUES (?,?,?,?,?,?)",
                        (client_id, client_name, serial, cert.decode(), "enabled", public_key),
                    )
                    db.executemany(
                        "INSERT INTO grants VALUES (?,?)",
                        [(client_id, n) for n in self.server.config.datasets],
                    )
                self.reply(
                    200,
                    {
                        "client_id": client_id,
                        "certificate": cert.decode(),
                        "ca_certificate": (
                            self.server.config.state_dir / "client-ca-cert.pem"
                        ).read_text(),
                    },
                )
            else:
                rotating_id = self.client_id()
                if rotating_id is None:
                    self.reply(403, {"error": "client not authorized"})
                    return
                cert = sign_client_csr(self.server.config.state_dir, csr, rotating_id)
                issued = x509.load_pem_x509_certificate(cert)
                serial = str(issued.serial_number)
                public_key = (
                    issued.public_key()
                    .public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    .hex()
                )
                with self.server.db() as db:
                    db.execute("INSERT INTO client_keys VALUES (?,?)", (public_key, rotating_id))
                    presented = x509.load_der_x509_certificate(
                        self.connection.getpeercert(binary_form=True)
                    )
                    db.execute(
                        "UPDATE clients SET previous_serial=CASE WHEN serial=? THEN serial ELSE previous_serial END, serial=?, certificate=?, public_key=? WHERE id=?",
                        (
                            str(presented.serial_number),
                            serial,
                            cert.decode(),
                            public_key,
                            rotating_id,
                        ),
                    )
                self.reply(
                    200,
                    {
                        "client_id": rotating_id,
                        "certificate": cert.decode(),
                        "ca_certificate": (
                            self.server.config.state_dir / "client-ca-cert.pem"
                        ).read_text(),
                    },
                )
        except (KeyError, ValueError, TypeError, json.JSONDecodeError, IndexError) as exc:
            self.reply(400, {"error": f"invalid request: {exc}"})
        except sqlite3.IntegrityError:
            self.reply(409, {"error": "client ID or public key already exists"})


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, server: DistributionServer):
        self.distribution = server
        runtime = Path(path).parent
        runtime.mkdir(parents=True, exist_ok=True)
        if Path(path).exists():
            Path(path).unlink()
        super().__init__(path, ControlHandler)
        os.chmod(path, 0o660)


class ControlHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request = json.loads(self.rfile.readline(4096))
        assert isinstance(self.server, ControlServer)
        server = self.server.distribution
        action = request.get("action")
        if action == "open":
            seconds = int(request["seconds"])
            if not 1 <= seconds <= 86400:
                response: dict[str, object] = {"error": "invalid duration"}
            else:
                until = server.open(seconds)
                response = {"until": dt.datetime.fromtimestamp(until).isoformat(timespec="seconds")}
        elif action == "close":
            server.close_window()
            response = {"closed": True}
        elif action == "status":
            response = {
                "running": True,
                "discovery": server.config.discovery,
                "remaining": server.remaining(),
                "server_id": server.server_id,
            }
        else:
            response = {"error": "unknown action"}
        self.wfile.write(json.dumps(response).encode() + b"\n")


def control(path: Path, action: str, seconds: int = 0) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(str(path))
        stream.sendall(json.dumps({"action": action, "seconds": seconds}).encode() + b"\n")
        data = stream.makefile("rb").readline(4096)
    return json.loads(data)
