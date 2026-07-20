"""Network-related enums for structured port and service data."""

from __future__ import annotations

from tarmo_vuln_core._compat import StrEnum


class Protocol(StrEnum):
    """Transport protocol."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class PortState(StrEnum):
    """Nmap-style port state."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNFILTERED = "unfiltered"


class ServiceName(StrEnum):
    """Common service names."""

    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    SMB = "smb"
    RDP = "rdp"
    TELNET = "telnet"
    OTHER = "other"
