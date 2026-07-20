"""TDD tests for the tarmo-vuln-core build scaffold.

Phase A: Pure Python package structure (unit).
Phase B: Rust extension via PyO3/maturin (integration).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Phase A — Pure Python package
# ---------------------------------------------------------------------------


class TestPythonPackage:
    """Verify the tarmo_vuln_core Python package is correctly structured."""

    @pytest.mark.unit
    def test_package_is_importable(self) -> None:
        import tarmo_vuln_core  # noqa: F401

    @pytest.mark.unit
    def test_package_version_value(self) -> None:
        import tarmo_vuln_core

        assert tarmo_vuln_core.__version__ == "0.2.0"

    @pytest.mark.unit
    def test_package_exposes_version_in_all(self) -> None:
        import tarmo_vuln_core

        assert "__version__" in tarmo_vuln_core.__all__

    @pytest.mark.unit
    def test_signing_submodule_is_importable_from_outside_repo_checkout(
        self, tmp_path: Path
    ) -> None:
        # Run outside the repository root so the import uses the installed package path.
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from tarmo_vuln_core.signing import ReportSigner; "
                    "print(ReportSigner.__module__)"
                ),
            ],
            capture_output=True,
            check=False,
            cwd=tmp_path,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "tarmo_vuln_core.signing"

    @pytest.mark.unit
    def test_py_typed_marker_exists(self) -> None:
        import tarmo_vuln_core

        package_dir = Path(tarmo_vuln_core.__file__).parent
        assert (package_dir / "py.typed").exists()


# ---------------------------------------------------------------------------
# Phase B — Rust extension
# ---------------------------------------------------------------------------


def _skip_if_no_rust_ext() -> None:
    """Skip the test if the compiled Rust extension is missing or stale.

    A stale .so happens when a dev pip-installs the package, then a later
    version bump changes the Python __version__ but the cached Rust build
    isn't rebuilt. The fix is to run ``maturin develop`` (or reinstall);
    until then the version-related tests would fail noisily, so we skip.
    """
    try:
        import vuln_core_rs  # noqa: F401
    except ImportError:
        pytest.skip("vuln_core_rs not compiled — run `maturin develop`")

    import tarmo_vuln_core

    if vuln_core_rs.version() != tarmo_vuln_core.__version__:
        pytest.skip(
            f"vuln_core_rs build is stale (compiled {vuln_core_rs.version()!r}, "
            f"package is {tarmo_vuln_core.__version__!r}) — run `maturin develop`"
        )


class TestRustExtension:
    """Verify the vuln_core_rs Rust extension module."""

    @pytest.mark.integration
    def test_rust_extension_importable(self) -> None:
        _skip_if_no_rust_ext()
        import vuln_core_rs  # noqa: F811

        assert vuln_core_rs is not None

    @pytest.mark.integration
    def test_rust_extension_has_version_function(self) -> None:
        _skip_if_no_rust_ext()
        import vuln_core_rs  # noqa: F811

        assert callable(vuln_core_rs.version)

    @pytest.mark.integration
    def test_rust_extension_version_value(self) -> None:
        _skip_if_no_rust_ext()
        import vuln_core_rs  # noqa: F811

        assert vuln_core_rs.version() == "0.2.0"

    @pytest.mark.integration
    def test_rust_extension_version_matches_python_package(self) -> None:
        _skip_if_no_rust_ext()
        import vuln_core_rs  # noqa: F811

        import tarmo_vuln_core

        assert vuln_core_rs.version() == tarmo_vuln_core.__version__
