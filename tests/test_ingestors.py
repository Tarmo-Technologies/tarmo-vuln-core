"""Tests for BaseIngestor, registry, auto_detect, get_by_format, and plugin loader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tarmo_vuln_core.ingestors import (
    REGISTRY,
    auto_detect,
    get_by_format,
    register_ingestor,
)
from tarmo_vuln_core.ingestors.base import BaseIngestor, IngestorError
from tarmo_vuln_core.ingestors.plugins import load_plugins
from tarmo_vuln_core.models.finding import Finding, Severity
from tarmo_vuln_core.models.host import Host

# ── Concrete test ingestor ──────────────────────────────────────────────────


class FakeIngestor(BaseIngestor):
    """Concrete ingestor for testing purposes."""

    def can_handle(self, path: Path) -> bool:
        return path.suffix == ".fake"

    def ingest(self, path: Path) -> list[Finding]:
        return [
            Finding(
                id="fake-1",
                title="Fake Finding",
                severity=Severity.LOW,
                description="A fake finding.",
                impact="None.",
                remediation="N/A.",
                source_tool="fake",
            )
        ]

    @property
    def supported_extensions(self) -> list[str]:
        return [".fake"]

    def ingest_hosts(self, path: Path) -> list[Host]:
        return [Host(address="10.0.0.99")]


class AnotherFakeIngestor(BaseIngestor):
    def can_handle(self, path: Path) -> bool:
        return path.suffix == ".another"

    def ingest(self, path: Path) -> list[Finding]:
        return []


# ── IngestorError ───────────────────────────────────────────────────────────


class TestIngestorError:
    def test_is_exception(self) -> None:
        assert issubclass(IngestorError, Exception)

    def test_preserves_message(self) -> None:
        err = IngestorError("something broke")
        assert str(err) == "something broke"


# ── BaseIngestor ABC ────────────────────────────────────────────────────────


class TestBaseIngestor:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            BaseIngestor()  # type: ignore[abstract]

    def test_concrete_subclass_works(self) -> None:
        ingestor = FakeIngestor()
        assert ingestor.can_handle(Path("test.fake")) is True
        assert ingestor.can_handle(Path("test.xml")) is False

    def test_supported_extensions_default_empty(self) -> None:
        ingestor = AnotherFakeIngestor()
        assert ingestor.supported_extensions == []

    def test_supported_extensions_override(self) -> None:
        ingestor = FakeIngestor()
        assert ingestor.supported_extensions == [".fake"]

    def test_ingest_hosts_default_empty(self) -> None:
        ingestor = AnotherFakeIngestor()
        assert ingestor.ingest_hosts(Path("test.another")) == []

    def test_ingest_hosts_override(self) -> None:
        ingestor = FakeIngestor()
        hosts = ingestor.ingest_hosts(Path("test.fake"))
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.99"


# ── Registry ────────────────────────────────────────────────────────────────


class TestRegistry:
    def test_starts_empty(self) -> None:
        # REGISTRY may have been modified by other tests; check type
        assert isinstance(REGISTRY, list)

    def test_register_ingestor(self) -> None:
        original_len = len(REGISTRY)
        fake = FakeIngestor()
        register_ingestor(fake)
        assert len(REGISTRY) == original_len + 1
        assert REGISTRY[-1] is fake
        # Cleanup
        REGISTRY.pop()


# ── auto_detect ─────────────────────────────────────────────────────────────


class TestAutoDetect:
    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            auto_detect(tmp_path / "nonexistent.xml")

    def test_no_handler_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "unknown.xyz"
        f.write_text("data")
        with pytest.raises(IngestorError, match="No ingestor could handle") as exc:
            auto_detect(f)
        msg = str(exc.value)
        assert "Coverity" in msg
        assert "Fortify" in msg

    def test_returns_matching_ingestor_via_extra(self, tmp_path: Path) -> None:
        f = tmp_path / "test.fake"
        f.write_text("fake data")
        result = auto_detect(f, extra=[FakeIngestor()])
        assert isinstance(result, FakeIngestor)

    def test_extra_param_extends_search(self, tmp_path: Path) -> None:
        f = tmp_path / "test.another"
        f.write_text("another data")
        result = auto_detect(f, extra=[AnotherFakeIngestor()])
        assert isinstance(result, AnotherFakeIngestor)


# ── get_by_format ───────────────────────────────────────────────────────────


class TestGetByFormat:
    def test_not_found_returns_none(self) -> None:
        assert get_by_format("nonexistent") is None

    def test_case_insensitive_match(self) -> None:
        fake = FakeIngestor()
        result = get_by_format("FAKE", extra=[fake])
        assert result is fake

    def test_lowercase_match(self) -> None:
        fake = FakeIngestor()
        result = get_by_format("fake", extra=[fake])
        assert result is fake

    def test_extra_param(self) -> None:
        another = AnotherFakeIngestor()
        result = get_by_format("anotherfake", extra=[another])
        assert result is another

    def test_snake_case_alias_for_camel_case_class(self) -> None:
        """OwaspDepcheckIngestor must be reachable via both 'owaspdepcheck' and 'owasp_depcheck'."""
        by_collapsed = get_by_format("owaspdepcheck")
        by_snake = get_by_format("owasp_depcheck")
        assert by_collapsed is not None
        assert by_snake is not None
        assert by_snake.__class__ is by_collapsed.__class__

    def test_all_registered_ingestors_resolve_both_forms(self) -> None:
        """Every built-in ingestor must resolve via collapsed and snake_case forms."""
        import re

        from tarmo_vuln_core.ingestors import REGISTRY

        for ingestor in REGISTRY:
            cls_name = ingestor.__class__.__name__.removesuffix("Ingestor")
            collapsed = cls_name.lower()
            snake = re.sub(r"(?<!^)(?=[A-Z])", "_", cls_name).lower()
            assert get_by_format(collapsed) is not None, (
                f"{cls_name}: collapsed form '{collapsed}' did not resolve"
            )
            assert get_by_format(snake) is not None, (
                f"{cls_name}: snake_case form '{snake}' did not resolve"
            )

    def test_snake_case_miss_still_returns_none(self) -> None:
        """Ensure new matcher doesn't produce false positives for arbitrary underscore inputs."""
        assert get_by_format("nonexistent_tool") is None
        assert get_by_format("nmap_") is None


# ── Plugin loader ───────────────────────────────────────────────────────────


class TestPluginLoader:
    def test_no_dirs_returns_empty(self, tmp_path: Path) -> None:
        # Point to a non-existent project dir and mock user dir
        with patch("tarmo_vuln_core.ingestors.plugins._USER_PLUGIN_DIR", tmp_path / "no-such-dir"):
            result = load_plugins(project_dir=tmp_path / "nonexistent")
        assert result == []

    def test_loads_from_project_dir(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / ".tarmo-vuln-core" / "ingestors"
        plugin_dir.mkdir(parents=True)
        plugin_file = plugin_dir / "my_plugin.py"
        plugin_file.write_text(
            "from pathlib import Path\n"
            "from tarmo_vuln_core.ingestors.base import BaseIngestor\n"
            "from tarmo_vuln_core.models.finding import Finding, Severity\n"
            "\n"
            "class MyPluginIngestor(BaseIngestor):\n"
            "    def can_handle(self, path: Path) -> bool:\n"
            "        return path.suffix == '.myplugin'\n"
            "    def ingest(self, path: Path) -> list[Finding]:\n"
            "        return []\n"
        )
        with patch("tarmo_vuln_core.ingestors.plugins._USER_PLUGIN_DIR", tmp_path / "no-user-dir"):
            result = load_plugins(project_dir=tmp_path)
        assert len(result) == 1
        ingestor, source = result[0]
        assert source == "project"
        assert ingestor.__class__.__name__ == "MyPluginIngestor"
        assert ingestor.can_handle(Path("test.myplugin")) is True

    def test_handles_invalid_files_gracefully(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / ".tarmo-vuln-core" / "ingestors"
        plugin_dir.mkdir(parents=True)
        bad_file = plugin_dir / "broken.py"
        bad_file.write_text("raise RuntimeError('broken on import')\n")
        with patch("tarmo_vuln_core.ingestors.plugins._USER_PLUGIN_DIR", tmp_path / "no-user-dir"):
            result = load_plugins(project_dir=tmp_path)
        assert result == []
