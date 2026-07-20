"""Shared host authorization primitives for the Tarmo tool family.

Provides the matching and checking logic used by both pentest-storm
(attack authorization) and pentest-scribe (reporting authorization).
Each tool defines its own SQLModel table and DB I/O; these functions
operate on any duck-typed sequence that satisfies the :class:`AuthRecord`
protocol.
"""

from __future__ import annotations

import contextlib
import ipaddress
from typing import Protocol, runtime_checkable


@runtime_checkable
class AuthRecord(Protocol):
    """Duck-typed interface for an authorization record.

    Any object with these three attributes is accepted by the shared
    helper functions — no SQLModel dependency required.
    """

    address_or_cidr: str
    status: str  # "authorized" | "denied"
    reason: str


class BaseAuthorizationError(Exception):
    """Raised when an operation targets hosts that are not authorized.

    Attributes:
        unauthorized: Hosts with no authorization record (unknown).
        denied: Hosts explicitly denied.
    """

    def __init__(self, unauthorized: list[str], denied: list[str]) -> None:
        self.unauthorized = unauthorized
        self.denied = denied
        parts: list[str] = []
        if unauthorized:
            parts.append(f"unauthorized: {', '.join(unauthorized)}")
        if denied:
            parts.append(f"denied: {', '.join(denied)}")
        super().__init__(f"Host authorization required — {'; '.join(parts)}")


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def strip_port(address: str) -> str:
    """Strip a trailing port from a host address.

    Handles IPv4 (``10.0.0.1:8080``), IPv6 (``[::1]:443``), and
    hostnames (``web.local:3001``).  Bare IPv6 addresses without brackets
    (e.g. ``2001:db8::1``) are returned unchanged.
    """
    if address.startswith("["):
        bracket_end = address.find("]")
        if bracket_end != -1:
            return address[1:bracket_end]
        return address
    if ":" in address and address.count(":") == 1:
        return address.rsplit(":", 1)[0]
    return address


def address_matches_scope_entry(address: str, entry: str) -> bool:
    """Return True if *address* equals *entry* or falls within the *entry* CIDR.

    Port suffixes on *address* are stripped before comparison.  Non-IP
    entries are compared by exact string equality only (no CIDR parse
    attempt).  Never raises.
    """
    base = strip_port(address)

    # Exact match (covers hostnames and plain IPs)
    if base == entry or address == entry:
        return True

    # CIDR containment
    target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    with contextlib.suppress(ValueError):
        target_ip = ipaddress.ip_address(base)

    if target_ip is not None:
        with contextlib.suppress(ValueError):
            network = ipaddress.ip_network(entry, strict=False)
            if target_ip in network:
                return True

    return False


# ---------------------------------------------------------------------------
# Record-level checking helpers
# ---------------------------------------------------------------------------


def check_address_in_records(address: str, records: list[AuthRecord]) -> tuple[bool, str | None]:
    """Check *address* against a list of authorization records.

    Returns:
        ``(True, None)`` if a matching "authorized" record is found.
        ``(False, reason)`` if a matching "denied" record is found.
        ``(False, None)`` if no matching record exists.

    First match wins — caller controls ordering.
    """
    for rec in records:
        if address_matches_scope_entry(address, rec.address_or_cidr):
            if rec.status == "authorized":
                return True, None
            return False, rec.reason or None
    return False, None


def get_unauthorized_from_records(
    addresses: list[str], records: list[AuthRecord]
) -> tuple[list[str], list[str]]:
    """Batch-check *addresses* against *records*.

    Returns:
        ``(unknown, denied)`` — two lists of addresses that are not
        authorized.  *unknown* has no matching record; *denied* is
        explicitly blocked.
    """
    unknown: list[str] = []
    denied: list[str] = []
    for addr in addresses:
        matched = next(
            (r for r in records if address_matches_scope_entry(addr, r.address_or_cidr)),
            None,
        )
        if matched is None:
            unknown.append(addr)
        elif matched.status == "authorized":
            pass  # authorized — skip
        else:
            denied.append(addr)
    return unknown, denied
