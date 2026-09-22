"""mDNS advertising and discovery."""

import ipaddress
import time
import uuid
from dataclasses import dataclass

import ifaddr
from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from . import defaults


@dataclass(frozen=True)
class FoundServer:
    name: str
    address: str
    port: int
    server_id: str

    @property
    def url(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"https://{host}:{self.port}"


def advertise(
    name: str, port: int, server_id: str, host: str = "0.0.0.0"
) -> tuple[Zeroconf, ServiceInfo]:
    addresses = []
    family = 6 if ":" in host else 4
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            raw = ip.ip if isinstance(ip.ip, str) else ip.ip[0]
            address = ipaddress.ip_address(raw)
            if (
                address.version == family
                and not (address.is_loopback or address.is_link_local or address.is_unspecified)
                and (host in ("0.0.0.0", "::") or str(address) == host)
            ):
                addresses.append(address.packed)
    if not addresses:
        raise RuntimeError("no usable IPv4 or IPv6 address for mDNS")
    zc = Zeroconf()
    service = ServiceInfo(
        defaults.SERVICE_TYPE,
        f"{name}.{defaults.SERVICE_TYPE}",
        addresses=sorted(set(addresses)),
        port=port,
        properties={"protocol": defaults.PROTOCOL, "server_id": server_id, "name": name},
        server=f"lan-distribution-{server_id[:8]}.local.",
    )
    zc.register_service(service, allow_name_change=True)
    return zc, service


def discover(timeout: float = 3.0) -> list[FoundServer]:
    zc = Zeroconf()
    found: dict[str, FoundServer] = {}

    class Listener(ServiceListener):
        def add_service(self, z: Zeroconf, service_type: str, service_name: str) -> None:
            info = z.get_service_info(service_type, service_name)
            if info is None or info.properties.get(b"protocol") != defaults.PROTOCOL.encode():
                return
            raw_id = info.properties.get(b"server_id")
            try:
                server_id = str(uuid.UUID(raw_id.decode("ascii"))) if raw_id else ""
            except (ValueError, UnicodeDecodeError):
                return
            addresses = []
            for raw in info.parsed_addresses():
                try:
                    address = ipaddress.ip_address(raw.split("%", 1)[0])
                except ValueError:
                    continue
                if not (address.is_link_local or address.is_loopback or address.is_unspecified):
                    addresses.append(address)
            if not server_id or not addresses or info.port is None or not 1 <= info.port <= 65535:
                return
            address = sorted(addresses, key=lambda item: (item.version != 4, str(item)))[0]
            found[service_name] = FoundServer(
                service_name.removesuffix("." + service_type),
                str(address),
                info.port,
                server_id,
            )

        def update_service(self, z: Zeroconf, service_type: str, service_name: str) -> None:
            self.add_service(z, service_type, service_name)

        def remove_service(self, z: Zeroconf, service_type: str, service_name: str) -> None:
            found.pop(service_name, None)

    browser = ServiceBrowser(zc, defaults.SERVICE_TYPE, Listener())
    time.sleep(timeout)
    browser.cancel()
    zc.close()
    unique: dict[tuple[str, str, int], FoundServer] = {}
    for server in sorted(found.values(), key=lambda x: (x.name, x.server_id, x.address, x.port)):
        unique.setdefault((server.server_id, server.address, server.port), server)
    return sorted(unique.values(), key=lambda x: (x.name, x.server_id, x.address, x.port))
