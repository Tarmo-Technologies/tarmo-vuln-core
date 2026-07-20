"""Tests for Host and HostProperty models."""

from __future__ import annotations

from tarmo_vuln_core.models.host import Host, HostProperty


class TestHostProperty:
    def test_creation(self) -> None:
        prop = HostProperty(key="os", value="Windows Server 2019")
        assert prop.key == "os"
        assert prop.value == "Windows Server 2019"

    def test_whitespace_stripping(self) -> None:
        prop = HostProperty(key="  hostname  ", value="  dc01.corp.local  ")
        assert prop.key == "hostname"
        assert prop.value == "dc01.corp.local"


class TestHost:
    def test_minimal(self) -> None:
        host = Host(address="10.0.0.1")
        assert host.address == "10.0.0.1"
        assert host.hostnames == []
        assert host.os is None
        assert host.os_confidence is None
        assert host.mac is None
        assert host.properties == []
        assert host.notes == ""

    def test_full(self) -> None:
        host = Host(
            address="10.0.0.1",
            hostnames=["host1.example.com", "web.example.com"],
            os="Linux 5.x",
            os_confidence=95,
            mac="AA:BB:CC:DD:EE:FF",
            notes="Primary web server",
        )
        assert host.hostnames == ["host1.example.com", "web.example.com"]
        assert host.os == "Linux 5.x"
        assert host.os_confidence == 95
        assert host.mac == "AA:BB:CC:DD:EE:FF"

    def test_with_properties(self) -> None:
        host = Host(
            address="10.0.0.1",
            properties=[
                HostProperty(key="port", value="22/tcp open ssh"),
                HostProperty(key="port", value="80/tcp open http"),
            ],
        )
        assert len(host.properties) == 2
        assert host.properties[0].key == "port"
        assert host.properties[0].value == "22/tcp open ssh"
