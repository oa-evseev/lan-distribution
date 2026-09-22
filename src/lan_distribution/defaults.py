"""Central deployment defaults."""

from pathlib import Path

ETC = Path("/etc/lan-distribution")
STATE = Path("/var/lib/lan-distribution")
RUNTIME = Path("/run/lan-distribution")
SOURCE = Path("/srv/lan-distribution")
SERVER_CONFIG = ETC / "server.toml"
CLIENT_CONFIG = ETC / "client.toml"
SERVER_STATE = STATE / "server"
CLIENT_STATE = STATE / "client"
CONTROL_SOCKET = RUNTIME / "server.sock"
SERVICE_TYPE = "_landist._tcp.local."
PROTOCOL = "1"
MAX_BODY = 40 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_ENTRIES = 10000
