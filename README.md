# lan-distribution

`lan-distribution` copies small, read-only file trees from one Linux server to local client replicas. Applications read ordinary local files. This is a one-way distributor, not a network filesystem or a writable sync tool.

The server is the source of truth. Each client is bound to one selected server and keeps the last valid version if that server is unavailable. Python 3.12+ is required; Ubuntu 24.04 is the target deployment. The service uses HTTPS, per-client mTLS identities, SQLite, and mDNS (`_landist._tcp.local.`).

The wire format and endpoint contract are in [docs/protocol.md](docs/protocol.md).

## Quick start

On the server:

```console
git clone https://github.com/oa-evseev/lan-distribution.git
cd lan-distribution
make install-server
```

The installer creates `/srv/lan-distribution/shared-config/`, server keys and database, default config, a dedicated `lan-distribution` system user, and an enabled service. The server advertises itself on the LAN. Registration starts **closed**. Put files in `/srv/lan-distribution/shared-config/`; the server reads this tree on demand. During an interactive server install it can offer to add the invoking user to the `lan-distribution` group, which permits administrative commands without `sudo`. The new membership takes effect after the next login session. Without that membership, use `sudo lan-distribution status`, `sudo lan-distribution open 2min`, and `sudo lan-distribution close`.

On a new client:

```console
git clone https://github.com/oa-evseev/lan-distribution.git
cd lan-distribution
make install

Discover lan-distribution servers on the local network? [Y/n] Y
Found 1 lan-distribution server(s):
  [1] lan-distribution
      192.0.2.10:9443
      id: <server-id>
Connect to this server? [Y/n/m]: Y
Found lan-distribution server:
  Name: lan-distribution
  Address: https://192.0.2.10:9443
  Server ID: <server-id>
  Fingerprint: SHA256:<fingerprint>
Trust this server? [y/N]: y
Can't register this client: server registration is closed.

On the server run:

    lan-distribution open 2min

Then press any key to retry enrollment (Ctrl-C to finish)...
```

On the server, while the client is waiting:

```console
sudo lan-distribution open 2min
```

Back on the client, press Enter. It prints `Registered successfully` and `Client service started.` The default application path is `/etc/lan-distribution/shared-config`, a symlink to the local versioned replica. A client installer run with `N` at the first prompt exits successfully without starting an unenrolled service. Enroll later with `sudo lan-distribution-client enroll`; then `sudo systemctl enable --now lan-distribution-client.service`.

`make install` and `make install-client` install the client role only. `make install-server` installs the server role only. The package is shared when both roles are present, while role commands and services are installed independently. The server administration command `lan-distribution` is installed with the server role. During an interactive client install, the installer can offer to add the invoking user to the `lan-distribution` group so `lan-distribution-client status` can run without `sudo`. The new membership takes effect after the next login session; without it, run `sudo lan-distribution-client status`.

## Discovery, trust, and enrollment

mDNS advertises a human-readable instance, port, protocol version, and stable server ID. Discovery does not depend on a DNS domain or a fixed address. If it finds several servers, the installer shows a numbered list and asks for a selection. With no servers it offers retry, manual HTTPS URL, or finish without enrollment. `lan-distribution-client discover` lists candidates; `lan-distribution-client enroll --url https://192.0.2.10:9443` starts manual bootstrap. If the same trusted server moves to another address, use `sudo lan-distribution-client reconnect --url https://192.0.2.11:9443`; it accepts the new address only when both the pinned certificate and stable ID match.

The first HTTPS connection retrieves the server certificate and shows its SHA-256 fingerprint and server ID for explicit trust confirmation. This initial probe cannot validate a self-signed certificate before the operator trusts it. After confirmation, the client pins the exact certificate and stable ID in `/var/lib/lan-distribution/client/trust.json`. All subsequent traffic requires TLS certificate validation against this pinned certificate; a changed identity fails. Verify the displayed fingerprint out of band when LAN discovery or active attackers are a concern. A server certificate is created during first install and is valid for ten years; replacing it currently requires deliberate client trust reset and re-enrollment.

The client creates an Ed25519 private key locally and sends only a CSR. The server's separate internal client-authentication CA signs a 30-day client certificate. Every registered API request uses mTLS. Keys never leave the client. The client checks on each regular cycle and rotates seven days before expiry with a fresh key. Rotation works while registration is closed. The previous certificate serial remains valid for one rotation overlap so an interrupted local credential switch can recover; further rotation replaces that overlap. If the client has lost its key or certificate entirely, open a new registration window and re-enroll. The server never persists the registration window: a restart closes it.

Commands on the server:

```console
sudo lan-distribution open 20sec
sudo lan-distribution open 2min
sudo lan-distribution close
sudo lan-distribution status
sudo lan-distribution-server clients
sudo lan-distribution-server client <client-id>
sudo lan-distribution-server disable <client-id>
sudo lan-distribution-server enable <client-id>
sudo lan-distribution-server revoke <client-id>
sudo lan-distribution-server grants <client-id>
sudo lan-distribution-server grant <client-id> shared-config
sudo lan-distribution-server deny <client-id> shared-config
sudo lan-distribution-server datasets
sudo lan-distribution-server publish test-pki /etc/example/pki-staging
```

`revoke` is permanent for that client ID; re-enrollment creates a new ID. Newly enrolled clients receive access to every configured dataset. Restrict that immediately with `deny` where needed, or change the policy before allowing enrollment. Disabled and revoked clients cannot use datasets or rotate. Enrollment windows do not affect registered clients.

## Datasets and replicas

Server config is `/etc/lan-distribution/server.toml`; the installer copies [config/server.toml](config/server.toml) only if absent. Add a named source directory inside `source_root`:

```toml
[datasets]
shared-config = "/srv/lan-distribution/shared-config"
test-pki = "/srv/lan-distribution/test-pki"
```

Those are source-backed datasets: the server snapshots their current source tree for each request. For content that must change as one unit (for example a certificate and private key), configure a server-managed published dataset instead:

```toml
[datasets.test-pki]
published = true
```

It has no mutable configured source. Publish a complete staging tree with `sudo lan-distribution-server publish test-pki /etc/example/pki-staging`. The server validates and privately copies it into `/var/lib/lan-distribution/server/datasets/test-pki/versions/<version-id>/`, then atomically replaces `current` with a symlink to that immutable version. Repeating identical content is a no-op. Old versions are retained (no automatic pruning in this release), so a client that has received a manifest always fetches that exact immutable version even if a later publication becomes current.

Restart the server after changing its config. A source tree may contain regular files and directories; symlinks, hard links, sockets, and special files are rejected. A dataset has a 32 MiB default source limit and a 40 MiB maximum response size. No arbitrary path can be requested through the API. For private source files, grant the dedicated `lan-distribution` user read access through ownership, a group, or ACLs; do not make secrets world-readable just to serve them.

Client config is `/etc/lan-distribution/client.toml`; the installer copies [config/client.toml](config/client.toml) only if absent. Configure the datasets this client should pull:

```toml
[client]
interval_seconds = 60

[datasets.shared-config]
target = "/etc/example/shared-config"
retain = 2
group = "example-service"
post_update = ["systemctl", "reload", "example-service"]
```

The client stores each version under `/var/lib/lan-distribution/client/datasets/<name>/versions/<SHA-256-manifest>/` and atomically switches `current` after the full TAR archive and every checksum have passed validation. An unchanged manifest is a NOOP. The stable target is a symlink to `current`; the client refuses to replace an unrelated existing file, directory, or symlink. `retain` keeps recent versions. `lan-distribution` preserves ordinary Unix permission bits (`0000..0777`) for regular files and directories. Files are owned locally by root, with an optional local `group` for non-root application readers. Source ownership, ACLs, xattrs, capabilities, and special mode bits are not replicated. Applications can traverse the replica path when directory modes permit it; credentials remain in a private directory. On connection failures, existing versions remain usable, and the daemon retries with a little jitter. Hooks run as an argv list after successful updates only, without a shell. Hook output and status go to the journal. A failed hook is reported while the newly installed version remains active.

Useful client commands:

```console
lan-distribution-client status # after joining lan-distribution and logging in again
sudo lan-distribution-client sync
sudo lan-distribution-client rotate
sudo lan-distribution-client validate
journalctl -u lan-distribution-client.service -f
```

See [config/server.example.toml](config/server.example.toml) and [config/client.example.toml](config/client.example.toml) for synthetic multi-dataset examples. `lan-distribution-server --help` and `lan-distribution-client --help` list all commands.

## Installation and removal

The installers require root or `sudo`, Python 3.12+, `venv`, `pip`, systemd, and network access to install PyPI dependencies. They install a shared application environment in `/opt/lan-distribution/venv` and public commands in `/usr/local/bin`. Re-running an installer preserves existing TOML, state, and identities. The server runs as the dedicated system user. The client service runs as root because admin-selected target paths can be under `/etc`; its unit applies limited systemd hardening. The server unit uses a read-only system view apart from its state and runtime directories.

The packaged systemd units use the default client and server state directories and the default server runtime directory. Installers reject a TOML that changes these paths; custom paths require a matching custom unit. Place server sources under `/srv/lan-distribution` for the packaged unit, and ensure the service user can read them.

Run `make uninstall` to remove all installed roles and their program files and units. It detects client only, server only, or both from units and command links. It preserves `/etc/lan-distribution`, `/var/lib/lan-distribution`, and `/srv/lan-distribution`. Repeated removal is safe. There is no implicit data purge. For a non-root rehearsal, set `DESTDIR` to an absolute temporary directory when running the installer or uninstaller; staged installs validate config and initialize server state without changing systemd.

## Security and operational limits

The LAN is trusted for discovery and for the operator's decision to open enrollment. Anyone on the LAN who can reach the server during an open window can enroll and initially receive all configured datasets. Keep windows short, inspect `lan-distribution-server clients`, and disable unwanted IDs. Use a firewall to restrict port 9443 to trusted networks. TLS and mTLS protect transport after explicit bootstrap trust. The server does not support certificate transparency, automated server certificate renewal, or shared trust across multiple servers. Exact server certificate pinning means server identity replacement needs operator action. Snapshot transfer is full-version, not delta sync, and is intended for small trees. mDNS generally stays within one multicast link; use a manual URL across routed networks.

## Troubleshooting

- No server found: check `systemctl status lan-distribution-server`, multicast/mDNS availability, and TCP port 9443. Use manual URL if multicast is unavailable.
- Registration closed: run `sudo lan-distribution open 2min` on the selected server, then retry only enrollment on the client.
- Target collision: move or rename the pre-existing target yourself, then run `sudo lan-distribution-client sync`. The client does not delete it.
- Dataset unauthorized: inspect `lan-distribution-server grants <client-id>` and use `grant` if appropriate.
- Server unavailable: the last local version remains active; inspect `journalctl -u lan-distribution-client.service` and network/firewall state.
- Identity lost: preserve local replicas, reopen registration, remove the broken `credentials/current` link only after backing up state, then run `lan-distribution-client enroll` and restart the client service. Revoke the old client ID on the server if its key may be compromised.

## Development

```console
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make test PYTHON=.venv/bin/python
make lint PYTHON=.venv/bin/python
make format PYTHON=.venv/bin/python
make check PYTHON=.venv/bin/python
```

The end-to-end test uses temporary directories and loopback HTTPS ports; it needs permission to create local sockets. `make check` runs pytest, Ruff lint, Ruff formatting check, mypy, shell syntax checks, and `git diff --check`.

MIT licensed; see [LICENSE](LICENSE).
