"""Shared fixtures for tarmo-vuln-core tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "unit: pure-Python unit tests")
    config.addinivalue_line("markers", "integration: tests requiring compiled Rust extension")
    config.addinivalue_line("markers", "real_fixture: tests validating real-world scanner output")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return the path to the test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture()
def sample_finding() -> object:
    """Return a minimal Finding instance for tests that need one."""
    from tarmo_vuln_core.models.finding import Finding, Severity

    return Finding(
        id="sample-finding",
        title="Sample Finding",
        severity=Severity.MEDIUM,
        description="A sample finding for testing.",
        impact="Sample impact.",
        remediation="Sample remediation.",
        source_tool="manual",
    )


@pytest.fixture()
def sample_host() -> object:
    """Return a minimal Host instance for tests that need one."""
    from tarmo_vuln_core.models.host import Host

    return Host(address="10.0.0.1", hostnames=["host1.example.com"])
