# Wire protocol v1

`lan-distribution` uses HTTPS over TCP. The default port is 9443. The server presents its persistent self-signed TLS certificate. During bootstrap, the client displays that certificate's SHA-256 fingerprint and the server ID for explicit trust approval. Thereafter, every request validates the exact pinned certificate and checks the `/v1/identity` server ID. IP addresses and DNS names are transport locations, not identities.

The mDNS service type is `_landist._tcp.local.`. TXT records include `protocol=1` and `server_id=<UUID>`. The SRV port points to the HTTPS service. A client can select among any number of advertisements or use a manual HTTPS URL. Discovery does not change an enrolled client's server binding.

## Endpoints

All JSON is UTF-8. Normal failures return `{"error":"..."}`. A client uses a locally generated Ed25519 private key and sends a PEM CSR; the private key is never sent.

| Method and path | Authentication | Behavior |
| --- | --- | --- |
| `GET /v1/identity` | TLS only | Returns `protocol`, `server_id`, and `name`. |
| `POST /v1/enroll` | TLS only; registration window open | Accepts `client_id` UUID, `name`, and PEM `csr`. Returns `client_id`, PEM `certificate`, and PEM `ca_certificate`. |
| `POST /v1/rotate` | mTLS; enabled client | Accepts PEM `csr` for the authenticated client ID. Returns the new certificate and CA certificate. Does not require registration to be open. |
| `GET /v1/datasets` | mTLS; enabled client | Returns authorized dataset names. |
| `GET /v1/datasets/<name>/manifest` | mTLS and dataset grant | Returns the current canonical manifest. |
| `GET /v1/datasets/<name>/archive` | mTLS and dataset grant | Returns an uncompressed TAR snapshot. |

Dataset names match `[a-z][a-z0-9_-]{0,63}`. Unauthenticated, unknown, disabled, revoked, or ungranted requests receive HTTP 403. Registration closed also returns 403 with `registration closed`; duplicate enrollment IDs return 409. A source snapshot failure returns 503. There is no endpoint to write dataset content.

The server authenticates client certificates against its separate client-auth CA, checks the certificate serial against SQLite, and checks enabled status and grants on every dataset request. Each certificate lasts 30 days. The client rotates seven days before expiry. One previous serial can remain valid during a rotation overlap, so a lost response or interrupted local switch does not immediately strand the client. Expired identities cannot authenticate and need a new enrollment window. The registration window lives only in process memory and starts closed after every server start.

## Manifest and archive

The manifest is JSON with exactly `entries` and `version`. Entries are sorted by path. Each directory entry has `path`, `type="dir"`, and a `mode` integer. Each file entry has `path`, `type="file"`, `mode`, `size`, and lowercase hexadecimal `sha256`. `mode` is part of the canonical metadata and is restricted to ordinary Unix permission bits `0o000..0o777`; it affects the version hash. The server derives it from `stat` as `mode & 0o777`. Ownership (uid/gid), ACLs, xattrs, capabilities, and setuid, setgid, and sticky bits are not transferred. Every non-root parent directory must also be listed. The version is lowercase hex SHA-256 of the entries array encoded as UTF-8 JSON with sorted keys, no insignificant whitespace, and `ensure_ascii=False`.

The archive contains exactly one TAR member per manifest entry, with matching types, paths, sizes, and file checksums. Paths are relative POSIX paths. Absolute paths, `..`, `.`, repeated separators, backslashes, NUL bytes, symlinks, links, devices, and unknown member types are rejected. Source hard links are also rejected. The client never uses `extractall`. It stages the complete version, creates files with mode `0000` while writing, applies the exact metadata mode only after content verification, then atomically replaces the `current` symlink. A manifest/archive race is detected by checksums and retried on a later cycle. The old local version stays active on failure.

Request JSON bodies are limited to 16 KiB. Server datasets default to 32 MiB of file content. Client responses are capped at 40 MiB including TAR overhead. Client HTTPS calls use 5 to 10 second timeouts; server request handlers use a 10 second timeout. The first version transfers a complete dataset whenever its manifest hash changes.

## Local administration

`lan-distribution open`, `close`, and `status` use `/run/lan-distribution/server.sock`, a permission-restricted Unix socket. This control channel is local to the server and is not an HTTPS endpoint. The CLI accepts `20sec`, `2min`, `15min`, `s`, `m`, and `h` forms, with a 24 hour maximum. Its open state is never stored in TOML or SQLite.
