"""Human-facing administration and client commands."""

import argparse
import logging
import re
import socket
import sqlite3
import sys
from pathlib import Path

from . import defaults
from .client import Client, ClientError, RegistrationClosed, probe
from .config import ConfigError, load_client, load_server, name
from .discovery import FoundServer, advertise, discover
from .server import DistributionServer, control, initialize


def duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(sec|min|s|m|h)", value)
    if not match:
        raise argparse.ArgumentTypeError("duration must be like 20sec or 2min")
    seconds = int(match[1]) * {"sec": 1, "s": 1, "min": 60, "m": 60, "h": 3600}[match[2]]
    if seconds > 86400:
        raise argparse.ArgumentTypeError("registration window cannot exceed 24 hours")
    return seconds


def choose(servers: list[FoundServer], answer: str) -> FoundServer | None:
    if answer.lower() in ("m", "manual"):
        return None
    if answer.isdecimal() and 1 <= int(answer) <= len(servers):
        return servers[int(answer) - 1]
    raise ValueError("invalid selection")


def select_server() -> tuple[str, str | None]:
    while True:
        servers = discover()
        if not servers:
            print("No lan-distribution servers found.")
            print("[R]etry discovery  [M]anual server URL  [F]inish without enrollment")
            answer = input("Select [R/m/f]: ").strip().lower() or "r"
            if answer == "r":
                continue
            if answer == "f":
                return "", None
            if answer == "m":
                return input("Server URL (https://host:port): ").strip(), None
            print("Invalid selection.")
            continue
        print(f"Found {len(servers)} lan-distribution server(s):")
        for index, server in enumerate(servers, 1):
            print(
                f"  [{index}] {server.name}\n      {server.address}:{server.port}\n      id: {server.server_id}"
            )
        print("  [M] Enter server URL manually")
        if len(servers) == 1:
            answer = input("Connect to this server? [Y/n/m]: ").strip().lower() or "y"
            if answer == "n":
                return "", None
            if answer == "y":
                return servers[0].url, servers[0].server_id
            if answer == "m":
                return input("Server URL (https://host:port): ").strip(), None
        else:
            answer = input(f"Select server [1-{len(servers)}/m]: ").strip()
            try:
                selected = choose(servers, answer)
                if selected is None:
                    return input("Server URL (https://host:port): ").strip(), None
                return selected.url, selected.server_id
            except ValueError:
                pass
        print("Invalid selection.")


def enroll_interactive(
    config_path: Path, url: str | None = None, expected_id: str | None = None
) -> int:
    client = Client(load_client(config_path))
    if client.credentials() is not None:
        print("Client is already enrolled.")
        return 0
    if (client.state / "trust.json").exists():
        trusted = client.trust()
        url = url or trusted["url"]
        expected_id = trusted["server_id"]
    elif not url:
        url, expected_id = select_server()
        if not url:
            print(
                "Installation complete without enrollment. Later run: lan-distribution-client enroll"
            )
            return 0
    identity, fingerprint = probe(url)
    if expected_id and identity["server_id"] != expected_id:
        raise ClientError("mDNS server ID does not match HTTPS server identity")
    if (client.state / "trust.json").exists():
        client.save_trust(identity)
    else:
        print(
            f"Found lan-distribution server:\n  Name: {identity['name']}\n  Address: {url}\n  Server ID: {identity['server_id']}\n  Fingerprint: {fingerprint}"
        )
        if input("Trust this server? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("Server was not trusted; enrollment skipped.")
            return 0
        client.save_trust(identity)
    while True:
        try:
            client_id = client.enroll(socket.gethostname())
            print(f"Registered successfully. Client ID: {client_id}")
            return 0
        except RegistrationClosed:
            print(
                "Can't register this client: server registration is closed.\n\nOn the server run:\n\n    lan-distribution open 2min\n"
            )
            try:
                input("Then press any key to retry enrollment (Ctrl-C to finish)...")
            except (KeyboardInterrupt, EOFError):
                print("\nEnrollment skipped. Later run: sudo lan-distribution-client enroll")
                return 0


def server_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lan-distribution-server")
    parser.add_argument("--config", type=Path, default=defaults.SERVER_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("init", "validate", "run", "clients", "datasets"):
        sub.add_parser(cmd)
    for cmd in ("client", "disable", "revoke", "enable", "grants"):
        sub.add_parser(cmd).add_argument("client_id")
    for cmd in ("grant", "deny"):
        p = sub.add_parser(cmd)
        p.add_argument("client_id")
        p.add_argument("dataset")
    return parser


def server_dispatch(args: argparse.Namespace) -> int:
    config = load_server(args.config)
    if args.command == "validate":
        print("Server configuration is valid.")
        return 0
    if args.command == "init":
        print(f"Server ID: {initialize(config)}")
        return 0
    if args.command == "run":
        server = DistributionServer(config)
        mdns = None
        try:
            if config.discovery:
                try:
                    mdns = advertise(
                        config.instance_name,
                        server.server_address[1],
                        server.server_id,
                        config.host,
                    )
                except (OSError, RuntimeError):
                    logging.exception("mDNS unavailable; HTTPS server remains available by URL")
            print(
                f"Server {server.server_id} listening on port {server.server_address[1]}",
                flush=True,
            )
            server.start()
        finally:
            if mdns:
                mdns[0].unregister_service(mdns[1])
                mdns[0].close()
            server.server_close()
        return 0
    if args.command == "datasets":
        for dataset, source in sorted(config.datasets.items()):
            print(f"{dataset}\t{source}")
        return 0
    with sqlite3.connect(config.state_dir / "server.db") as db:
        if args.command == "clients":
            for row in db.execute("SELECT id,name,status FROM clients ORDER BY name"):
                print("\t".join(row))
        elif args.command in ("client", "grants"):
            row = db.execute(
                "SELECT id,name,status FROM clients WHERE id=?", (args.client_id,)
            ).fetchone()
            if row is None:
                raise ValueError("client not found")
            print(f"Client: {row[0]}\nName: {row[1]}\nStatus: {row[2]}")
            for grant in db.execute(
                "SELECT dataset FROM grants WHERE client_id=? ORDER BY dataset", (args.client_id,)
            ):
                print(f"Grant: {grant[0]}")
        elif args.command in ("disable", "revoke", "enable"):
            state = (
                "enabled"
                if args.command == "enable"
                else "disabled"
                if args.command == "disable"
                else "revoked"
            )
            result = db.execute(
                "UPDATE clients SET status=? WHERE id=? AND status!='revoked'",
                (state, args.client_id),
            )
            if result.rowcount != 1:
                raise ValueError("client not found or permanently revoked")
            print(f"Client {args.client_id}: {state}")
        elif args.command in ("grant", "deny"):
            dataset = name(args.dataset)
            if dataset not in config.datasets:
                raise ValueError("dataset is not configured")
            if not db.execute("SELECT 1 FROM clients WHERE id=?", (args.client_id,)).fetchone():
                raise ValueError("client not found")
            if args.command == "grant":
                db.execute("INSERT OR IGNORE INTO grants VALUES (?,?)", (args.client_id, dataset))
            else:
                db.execute(
                    "DELETE FROM grants WHERE client_id=? AND dataset=?", (args.client_id, dataset)
                )
            print(f"{args.command}: {args.client_id} {dataset}")
    return 0


def client_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lan-distribution-client")
    parser.add_argument("--config", type=Path, default=defaults.CLIENT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("discover", "validate", "sync", "run", "status", "rotate"):
        sub.add_parser(cmd)
    sub.add_parser("enroll").add_argument("--url")
    sub.add_parser("reconnect").add_argument("--url", required=True)
    return parser


def client_dispatch(args: argparse.Namespace) -> int:
    if args.command == "discover":
        for server in discover():
            print(f"{server.name}\t{server.url}\t{server.server_id}")
        return 0
    config = load_client(args.config)
    if args.command == "validate":
        print("Client configuration is valid.")
        return 0
    if args.command == "enroll":
        return enroll_interactive(args.config, args.url)
    client = Client(config)
    if args.command == "reconnect":
        client.reconnect(args.url)
        print("Server URL updated after identity verification.")
        return 0
    if args.command == "status":
        try:
            trust = client.trust()
            print(f"Server ID: {trust['server_id']}\nServer URL: {trust['url']}")
            print(f"Enrolled: {'yes' if client.credentials() else 'no'}")
        except ClientError:
            print("Enrolled: no")
        return 0
    if args.command == "rotate":
        client.rotate()
        print("Client identity rotated.")
    elif args.command == "sync":
        for dataset, changed in client.sync().items():
            print(f"{dataset}: {'updated' if changed else 'no change'}")
    elif args.command == "run":
        client.run()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="lan-distribution", description="Server registration window administration"
    )
    parser.add_argument("--socket", type=Path, default=defaults.CONTROL_SOCKET)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("open").add_argument("duration", type=duration)
    sub.add_parser("close")
    sub.add_parser("status")
    args = parser.parse_args()
    try:
        response = control(args.socket, args.command, getattr(args, "duration", 0))
        if args.command == "open":
            print(
                f"Client registration enabled for {args.duration // 60} minutes."
                if args.duration % 60 == 0
                else f"Client registration enabled for {args.duration} seconds."
            )
            print(f"Registration closes at {response['until']}.")
        elif args.command == "close":
            print("Client registration closed.")
        else:
            remaining = int(str(response["remaining"]))
            print(
                f"Server: running\nDiscovery: {'enabled' if response['discovery'] else 'disabled'}\nRegistration: {'open' if remaining else 'closed'}\nRegistration window remaining: {remaining} seconds"
            )
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def server_main() -> int:
    args = server_parser().parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        return server_dispatch(args)
    except (ConfigError, ValueError, OSError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def client_main() -> int:
    args = client_parser().parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        return client_dispatch(args)
    except (ConfigError, ClientError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
