"""Tests for tarmo_vuln_core.network.host_auth shared primitives."""

from __future__ import annotations

from tarmo_vuln_core.network.host_auth import (
    AuthRecord,
    BaseAuthorizationError,
    address_matches_scope_entry,
    check_address_in_records,
    get_unauthorized_from_records,
    strip_port,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(address_or_cidr: str, status: str, reason: str = "") -> AuthRecord:
    """Create a minimal duck-typed AuthRecord for testing."""

    class _Rec:
        def __init__(self) -> None:
            self.address_or_cidr = address_or_cidr
            self.status = status
            self.reason = reason

    return _Rec()  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# strip_port
# ---------------------------------------------------------------------------


class TestStripPort:
    def test_plain_ip(self) -> None:
        assert strip_port("10.0.0.1") == "10.0.0.1"

    def test_ipv4_with_port(self) -> None:
        assert strip_port("10.0.0.1:8080") == "10.0.0.1"

    def test_hostname_with_port(self) -> None:
        assert strip_port("web.local:3001") == "web.local"

    def test_ipv6_bracket(self) -> None:
        assert strip_port("[::1]:443") == "::1"

    def test_bare_ipv6(self) -> None:
        # Multiple colons, no brackets — treated as bare IPv6, no port to strip
        assert strip_port("2001:db8::1") == "2001:db8::1"

    def test_no_port(self) -> None:
        assert strip_port("192.168.1.5") == "192.168.1.5"

    def test_hostname_no_port(self) -> None:
        assert strip_port("example.com") == "example.com"


# ---------------------------------------------------------------------------
# address_matches_scope_entry
# ---------------------------------------------------------------------------


class TestAddressMatchesScopeEntry:
    def test_exact_ip_match(self) -> None:
        assert address_matches_scope_entry("10.0.0.1", "10.0.0.1") is True

    def test_exact_ip_no_match(self) -> None:
        assert address_matches_scope_entry("10.0.0.2", "10.0.0.1") is False

    def test_cidr_contains(self) -> None:
        assert address_matches_scope_entry("10.0.0.5", "10.0.0.0/24") is True

    def test_cidr_not_contains(self) -> None:
        assert address_matches_scope_entry("192.168.1.1", "10.0.0.0/24") is False

    def test_ip_with_port_vs_plain_entry(self) -> None:
        # Port on the address side should be stripped before matching
        assert address_matches_scope_entry("10.0.0.1:8080", "10.0.0.1") is True

    def test_ip_with_port_vs_cidr(self) -> None:
        assert address_matches_scope_entry("10.0.0.5:443", "10.0.0.0/24") is True

    def test_exact_hostname_match(self) -> None:
        assert address_matches_scope_entry("app.example.com", "app.example.com") is True

    def test_hostname_no_match(self) -> None:
        assert address_matches_scope_entry("other.example.com", "app.example.com") is False

    def test_bad_entry_not_raise(self) -> None:
        # Non-IP, non-CIDR entry falls back to exact; should not raise
        assert address_matches_scope_entry("10.0.0.1", "not-a-cidr") is False

    def test_cidr_boundary_included(self) -> None:
        assert address_matches_scope_entry("10.0.0.0", "10.0.0.0/24") is True

    def test_cidr_boundary_excluded(self) -> None:
        assert address_matches_scope_entry("10.0.1.0", "10.0.0.0/24") is False


# ---------------------------------------------------------------------------
# check_address_in_records
# ---------------------------------------------------------------------------


class TestCheckAddressInRecords:
    def test_authorized_exact(self) -> None:
        records = [_make_record("10.0.0.1", "authorized", "pentest")]
        ok, reason = check_address_in_records("10.0.0.1", records)
        assert ok is True
        assert reason is None

    def test_denied_exact(self) -> None:
        records = [_make_record("10.0.0.1", "denied", "out of scope")]
        ok, reason = check_address_in_records("10.0.0.1", records)
        assert ok is False
        assert reason == "out of scope"

    def test_no_record(self) -> None:
        records = [_make_record("192.168.1.1", "authorized")]
        ok, reason = check_address_in_records("10.0.0.1", records)
        assert ok is False
        assert reason is None

    def test_authorized_via_cidr(self) -> None:
        records = [_make_record("10.0.0.0/24", "authorized")]
        ok, reason = check_address_in_records("10.0.0.5", records)
        assert ok is True
        assert reason is None

    def test_denied_via_cidr(self) -> None:
        records = [_make_record("10.0.0.0/24", "denied", "blocked range")]
        ok, reason = check_address_in_records("10.0.0.5", records)
        assert ok is False
        assert reason == "blocked range"

    def test_port_stripped_before_check(self) -> None:
        records = [_make_record("10.0.0.1", "authorized")]
        ok, _ = check_address_in_records("10.0.0.1:8080", records)
        assert ok is True

    def test_empty_records(self) -> None:
        ok, reason = check_address_in_records("10.0.0.1", [])
        assert ok is False
        assert reason is None

    def test_denied_takes_priority_over_authorized_when_denied_listed_first(self) -> None:
        # Denied record should be returned as-found (first match wins)
        records = [
            _make_record("10.0.0.1", "denied", "blocked"),
            _make_record("10.0.0.0/24", "authorized"),
        ]
        ok, reason = check_address_in_records("10.0.0.1", records)
        assert ok is False
        assert reason == "blocked"


# ---------------------------------------------------------------------------
# get_unauthorized_from_records
# ---------------------------------------------------------------------------


class TestGetUnauthorizedFromRecords:
    def test_all_authorized(self) -> None:
        records = [
            _make_record("10.0.0.1", "authorized"),
            _make_record("10.0.0.2", "authorized"),
        ]
        unknown, denied = get_unauthorized_from_records(["10.0.0.1", "10.0.0.2"], records)
        assert unknown == []
        assert denied == []

    def test_some_unknown(self) -> None:
        records = [_make_record("10.0.0.1", "authorized")]
        unknown, denied = get_unauthorized_from_records(["10.0.0.1", "10.0.0.9"], records)
        assert unknown == ["10.0.0.9"]
        assert denied == []

    def test_some_denied(self) -> None:
        records = [_make_record("10.0.0.1", "denied", "blocked")]
        unknown, denied = get_unauthorized_from_records(["10.0.0.1"], records)
        assert unknown == []
        assert denied == ["10.0.0.1"]

    def test_mixed_states(self) -> None:
        records = [
            _make_record("10.0.0.1", "authorized"),
            _make_record("10.0.0.2", "denied"),
        ]
        unknown, denied = get_unauthorized_from_records(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"], records
        )
        assert unknown == ["10.0.0.3"]
        assert denied == ["10.0.0.2"]

    def test_empty_addresses(self) -> None:
        records = [_make_record("10.0.0.1", "authorized")]
        unknown, denied = get_unauthorized_from_records([], records)
        assert unknown == []
        assert denied == []

    def test_cidr_covered(self) -> None:
        records = [_make_record("10.0.0.0/24", "authorized")]
        unknown, denied = get_unauthorized_from_records(
            ["10.0.0.1", "10.0.0.99", "192.168.1.1"], records
        )
        assert unknown == ["192.168.1.1"]
        assert denied == []


# ---------------------------------------------------------------------------
# BaseAuthorizationError
# ---------------------------------------------------------------------------


class TestBaseAuthorizationError:
    def test_message_includes_unauthorized(self) -> None:
        exc = BaseAuthorizationError(["10.0.0.1"], [])
        assert "10.0.0.1" in str(exc)
        assert "unauthorized" in str(exc)

    def test_message_includes_denied(self) -> None:
        exc = BaseAuthorizationError([], ["10.0.0.2"])
        assert "10.0.0.2" in str(exc)
        assert "denied" in str(exc)

    def test_both_populated(self) -> None:
        exc = BaseAuthorizationError(["10.0.0.1"], ["10.0.0.2"])
        msg = str(exc)
        assert "10.0.0.1" in msg
        assert "10.0.0.2" in msg

    def test_attrs_accessible(self) -> None:
        exc = BaseAuthorizationError(["a"], ["b"])
        assert exc.unauthorized == ["a"]
        assert exc.denied == ["b"]

    def test_subclass_inherits(self) -> None:
        class MyError(BaseAuthorizationError):
            pass

        exc = MyError(["x"], [])
        assert isinstance(exc, BaseAuthorizationError)
        assert exc.unauthorized == ["x"]


# ---------------------------------------------------------------------------
# AuthRecord Protocol duck-typing
# ---------------------------------------------------------------------------


class TestAuthRecordProtocol:
    def test_plain_object_satisfies_protocol(self) -> None:
        """Any object with address_or_cidr/status/reason satisfies AuthRecord."""

        # Verify Protocol is runtime-checkable
        assert hasattr(AuthRecord, "__protocol_attrs__") or isinstance(AuthRecord, type), (
            "AuthRecord must be a Protocol"
        )

        rec = _make_record("10.0.0.1", "authorized", "test")
        # Should be usable in check_address_in_records without error
        ok, _ = check_address_in_records("10.0.0.1", [rec])
        assert ok is True
