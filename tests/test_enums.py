"""Tests for Protocol, PortState, and ServiceName enums."""

from __future__ import annotations

from tarmo_vuln_core.models.enums import PortState, Protocol, ServiceName


class TestProtocol:
    def test_values(self) -> None:
        assert Protocol.TCP == "tcp"
        assert Protocol.UDP == "udp"
        assert Protocol.SCTP == "sctp"

    def test_member_count(self) -> None:
        assert len(Protocol) == 3


class TestPortState:
    def test_values(self) -> None:
        assert PortState.OPEN == "open"
        assert PortState.CLOSED == "closed"
        assert PortState.FILTERED == "filtered"
        assert PortState.OPEN_FILTERED == "open|filtered"
        assert PortState.CLOSED_FILTERED == "closed|filtered"
        assert PortState.UNFILTERED == "unfiltered"

    def test_member_count(self) -> None:
        assert len(PortState) == 6


class TestServiceName:
    def test_values(self) -> None:
        assert ServiceName.HTTP == "http"
        assert ServiceName.HTTPS == "https"
        assert ServiceName.SSH == "ssh"
        assert ServiceName.FTP == "ftp"
        assert ServiceName.SMTP == "smtp"
        assert ServiceName.DNS == "dns"
        assert ServiceName.SMB == "smb"
        assert ServiceName.RDP == "rdp"
        assert ServiceName.TELNET == "telnet"
        assert ServiceName.OTHER == "other"

    def test_member_count(self) -> None:
        assert len(ServiceName) == 10
