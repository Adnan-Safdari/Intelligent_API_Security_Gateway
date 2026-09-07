"""
Prove the gateway believes our addresses before generating anything.

The gateway trusts X-Forwarded-For only from a configured trusted proxy.
config.yaml trusts 172.16.0.0/12, which Compose usually lands in -- but Docker
Desktop sometimes allocates 192.168.65.0/24 instead, and then every persona
collapses into one address with no error anywhere. The run completes, the files
look right, and the dataset is silently one client pretending to be forty.

There is no way to detect that afterwards, so it is detected before: send one
request per address, read back what the gateway recorded, and refuse to start
if it recorded something else. This turns silent data corruption into a startup
failure, which is the only trade worth making here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

IP_LATEST = "iasg:ip:{ip}:latest"


class IdentityNotTrusted(RuntimeError):
    """Raised before any traffic is generated. Never downgraded to a warning:
    a warning here produces a dataset that is wrong in a way nothing downstream
    can see."""


@dataclass
class PreflightResult:
    trusted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    # What the gateway recorded instead. One address here for every persona is
    # the collapse case, and naming it is what makes the error actionable.
    observed_instead: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing


def preflight(
    addresses: Sequence[str],
    send: Callable[[str], None],
    lookup: Callable[[str], str | None],
    observed: Callable[[], Iterable[str]] | None = None,
) -> PreflightResult:
    """
    Send one request as each address, then check the gateway agreed.

    send(ip) drives one request with that X-Forwarded-For. lookup(key) reads a
    Redis key. observed() lists the addresses the gateway did record, used only
    to make the failure message name the collapsed address.
    """
    for ip in addresses:
        send(ip)

    result = PreflightResult()
    for ip in addresses:
        if lookup(IP_LATEST.format(ip=ip)):
            result.trusted.append(ip)
        else:
            result.missing.append(ip)

    if result.missing and observed is not None:
        result.observed_instead = sorted(set(observed()) - set(addresses))
    return result


def require_trusted_identity(result: PreflightResult) -> None:
    if result.ok:
        return

    detail = [
        f"the gateway did not record {len(result.missing)} of "
        f"{len(result.missing) + len(result.trusted)} persona addresses",
        f"missing: {', '.join(result.missing[:5])}"
        + (" ..." if len(result.missing) > 5 else ""),
    ]
    if result.observed_instead:
        detail.append(
            "it recorded these instead: " + ", ".join(result.observed_instead[:5])
        )
        detail.append(
            "that is the peer address -- X-Forwarded-For is not being believed. "
            "Add its network to trusted_proxies in gateway/configs/config.yaml, "
            "or drive traffic from a container on the compose network."
        )
    else:
        detail.append(
            "no addresses were recorded at all: check the gateway is up and "
            "Redis is reachable."
        )
    raise IdentityNotTrusted("\n  ".join(detail))


def observed_addresses(keys: Callable[[str], Iterable[str]]) -> list[str]:
    """Turn iasg:ip:<ip>:latest keys back into addresses."""
    out = []
    for key in keys("iasg:ip:*:latest"):
        parts = key.split(":")
        if len(parts) >= 4:
            out.append(":".join(parts[2:-1]))
    return out


def peer_network(address: str) -> str:
    """
    The /24 an unexpected address sits in, for the error message.

    Reported rather than added to any list: widening trusted_proxies is a
    security decision, and this is a test harness.
    """
    parts = address.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return address
