"""Regression tests for the Python 3.10 / 3.11+ datetime.UTC compat shim."""

from __future__ import annotations

import datetime as dt
import importlib

import pytest


def test_utc_is_a_tzinfo() -> None:
    """UTC must be a usable tzinfo on whatever Python is running."""
    from tarmo_vuln_core._compat import UTC

    now = dt.datetime.now(UTC)
    assert now.tzinfo is not None


def test_utc_falls_back_to_timezone_utc_on_simulated_3_10() -> None:
    """When ``datetime.UTC`` is unavailable (Python 3.10), the shim must
    fall back to ``datetime.timezone.utc``."""
    saved = getattr(dt, "UTC", None)
    try:
        if hasattr(dt, "UTC"):
            del dt.UTC  # simulate 3.10
        # Re-import the compat module to trigger the ImportError branch.
        import tarmo_vuln_core._compat as compat_mod

        importlib.reload(compat_mod)
        assert compat_mod.UTC is dt.timezone.utc  # noqa: UP017 — testing the 3.10 fallback explicitly
    finally:
        if saved is not None:
            dt.UTC = saved
        # Restore the live module so other tests see the current Python's UTC.
        import tarmo_vuln_core._compat as compat_mod

        importlib.reload(compat_mod)


@pytest.mark.parametrize(
    "module_path",
    [
        "tarmo_vuln_core.signing.keygen",
        "tarmo_vuln_core.signing.detached_signer",
    ],
)
def test_signing_modules_import_without_native_utc(module_path: str) -> None:
    """Modules that previously did ``datetime.UTC`` must still import
    when ``datetime.UTC`` is unavailable."""
    saved = getattr(dt, "UTC", None)
    try:
        if hasattr(dt, "UTC"):
            del dt.UTC
        # Reload _compat first so its UTC attribute reflects the simulated 3.10.
        import tarmo_vuln_core._compat as compat_mod

        importlib.reload(compat_mod)
        # Reload the consumer; should not raise.
        consumer = importlib.import_module(module_path)
        importlib.reload(consumer)
    finally:
        if saved is not None:
            dt.UTC = saved
        import tarmo_vuln_core._compat as compat_mod

        importlib.reload(compat_mod)


def test_strenum_works_on_3_10() -> None:
    """The StrEnum polyfill must produce a class that compares with str values."""
    from tarmo_vuln_core._compat import StrEnum

    class Color(StrEnum):
        RED = "red"
        BLUE = "blue"

    assert Color.RED == "red"
    assert str(Color.RED) == "red"
    assert isinstance(Color.RED, str)
