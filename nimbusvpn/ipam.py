"""IP address management for the VPN subnets.

The server takes the first host address. Each device gets the lowest free IPv4 host
address; when IPv6 is enabled the device's IPv6 address uses the same host offset, so
``10.8.0.7`` pairs with ``fd42:4e:42::7``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class AddressPoolExhausted(RuntimeError):
    pass


def server_addresses(
    v4: ipaddress.IPv4Network, v6: ipaddress.IPv6Network | None
) -> tuple[ipaddress.IPv4Address, ipaddress.IPv6Address | None]:
    return v4.network_address + 1, (v6.network_address + 1 if v6 else None)


def allocate(
    v4: ipaddress.IPv4Network,
    v6: ipaddress.IPv6Network | None,
    used_v4: Iterable[str],
) -> tuple[str, str | None]:
    taken = {int(ipaddress.IPv4Address(ip)) for ip in used_v4}
    base = int(v4.network_address)
    # Offsets 0 (network), 1 (server) and the broadcast address are reserved.
    for offset in range(2, v4.num_addresses - 1):
        if base + offset not in taken:
            ipv6 = str(v6.network_address + offset) if v6 else None
            return str(ipaddress.IPv4Address(base + offset)), ipv6
    raise AddressPoolExhausted(f"no free addresses left in {v4}")


def capacity(v4: ipaddress.IPv4Network) -> int:
    return v4.num_addresses - 3
