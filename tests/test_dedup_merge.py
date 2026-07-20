"""Tests for tarmo_vuln_core.dedup.merge — finding/instance merge logic."""

from __future__ import annotations

from datetime import UTC, datetime

from tarmo_vuln_core.models import Finding, FindingStatus, Instance, Severity

# ── merge_instances ──────────────────────────────────────────────────────────


class TestMergeInstances:
    """merge_instances unions by (host, port, path); old state wins on conflict."""

    def test_old_state_wins_on_conflict(self):
        from tarmo_vuln_core.dedup.merge import merge_instances

        ts = datetime(2026, 1, 15, tzinfo=UTC)
        old = [
            Instance(host="10.0.0.1", port=443, status=FindingStatus.VERIFIED, verified_at=ts),
        ]
        new = [
            Instance(host="10.0.0.1", port=443, status=FindingStatus.OPEN),
        ]
        result = merge_instances(old, new)
        assert len(result) == 1
        assert result[0].status == FindingStatus.VERIFIED
        assert result[0].verified_at == ts

    def test_new_location_appended(self):
        from tarmo_vuln_core.dedup.merge import merge_instances

        old = [Instance(host="10.0.0.1", port=80)]
        new = [Instance(host="10.0.0.2", port=443)]
        result = merge_instances(old, new)
        assert len(result) == 2
        hosts = {i.host for i in result}
        assert hosts == {"10.0.0.1", "10.0.0.2"}

    def test_path_included_in_key(self):
        from tarmo_vuln_core.dedup.merge import merge_instances

        old = [Instance(host="10.0.0.1", port=443, path="/login")]
        new = [Instance(host="10.0.0.1", port=443, path="/admin")]
        result = merge_instances(old, new)
        assert len(result) == 2

    def test_empty_old_returns_new(self):
        from tarmo_vuln_core.dedup.merge import merge_instances

        new = [Instance(host="10.0.0.1", port=80)]
        result = merge_instances([], new)
        assert len(result) == 1
        assert result[0].host == "10.0.0.1"

    def test_empty_new_returns_old(self):
        from tarmo_vuln_core.dedup.merge import merge_instances

        old = [Instance(host="10.0.0.1", port=80)]
        result = merge_instances(old, [])
        assert len(result) == 1
        assert result[0].host == "10.0.0.1"


# ── merge_findings ───────────────────────────────────────────────────────────


def _make_finding(**overrides) -> Finding:
    defaults = {
        "id": "ssl-weak-cipher",
        "title": "SSL Weak Cipher",
        "severity": Severity.MEDIUM,
        "description": "Weak cipher detected.",
        "impact": "Data exposure.",
        "remediation": "Disable weak ciphers.",
        "source_tool": "nessus",
        "affected_hosts": ["10.0.0.1"],
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestMergeFindings:
    """merge_findings handles same-id re-ingest and cross-tool dedup."""

    def test_same_id_reingest_new_content_wins(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(description="Old desc", status=FindingStatus.VERIFIED)
        new = _make_finding(description="New desc", status=FindingStatus.OPEN)
        merged = merge_findings(old, new)
        # New content wins
        assert merged.description == "New desc"
        # Assessor fields preserved from old
        assert merged.status == FindingStatus.VERIFIED

    def test_same_id_reingest_merges_hosts(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(affected_hosts=["10.0.0.1"])
        new = _make_finding(affected_hosts=["10.0.0.2"])
        merged = merge_findings(old, new)
        assert merged.affected_hosts == ["10.0.0.1", "10.0.0.2"]

    def test_same_id_reingest_merges_source_tools(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(source_tool="nessus", source_tools=["nessus"])
        new = _make_finding(source_tool="openvas")
        merged = merge_findings(old, new)
        assert "nessus" in merged.source_tools
        assert "openvas" in merged.source_tools

    def test_cross_tool_dedup_old_content_wins(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(id="ssl-weak-cipher", description="Old canonical desc")
        new = _make_finding(id="nessus-plugin-42873", description="Scanner desc")
        merged = merge_findings(old, new)
        # Old (canonical) wins for content in cross-tool dedup
        assert merged.description == "Old canonical desc"
        assert merged.id == "ssl-weak-cipher"

    def test_higher_cvss_wins(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(cvss_score=5.0, cvss_version="3.1")
        new = _make_finding(cvss_score=7.5, cvss_version="3.1")
        merged = merge_findings(old, new)
        assert merged.cvss_score == 7.5

    def test_old_cvss_wins_when_equal(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(cvss_score=7.5, cvss_version="3.1")
        new = _make_finding(cvss_score=7.5, cvss_version="4.0")
        merged = merge_findings(old, new)
        assert merged.cvss_version == "3.1"

    def test_none_old_cvss_takes_new(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(cvss_score=None)
        new = _make_finding(cvss_score=6.1, cvss_version="3.1")
        merged = merge_findings(old, new)
        assert merged.cvss_score == 6.1
        assert merged.cvss_version == "3.1"

    def test_assessor_lifecycle_fields_preserved(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        ts = datetime(2026, 2, 1, tzinfo=UTC)
        old = _make_finding(
            status=FindingStatus.RESOLVED,
            remediated_at=ts,
            verified_at=ts,
            notes="Patched in sprint 12",
        )
        new = _make_finding(status=FindingStatus.OPEN, notes="")
        merged = merge_findings(old, new)
        assert merged.status == FindingStatus.RESOLVED
        assert merged.remediated_at == ts
        assert merged.verified_at == ts
        assert merged.notes == "Patched in sprint 12"

    def test_instances_merged(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(instances=[Instance(host="10.0.0.1", port=443)])
        new = _make_finding(instances=[Instance(host="10.0.0.2", port=80)])
        merged = merge_findings(old, new)
        assert len(merged.instances) == 2

    def test_no_duplicate_hosts(self):
        from tarmo_vuln_core.dedup.merge import merge_findings

        old = _make_finding(affected_hosts=["10.0.0.1", "10.0.0.2"])
        new = _make_finding(affected_hosts=["10.0.0.2", "10.0.0.3"])
        merged = merge_findings(old, new)
        assert merged.affected_hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
