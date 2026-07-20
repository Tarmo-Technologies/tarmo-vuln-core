"""Unit tests for the TruffleHog JSON-lines ingestor."""

from __future__ import annotations

from pathlib import Path

import pytest

from tarmo_vuln_core.ingestors.base import IngestorError
from tarmo_vuln_core.ingestors.parsers.trufflehog import TrufflehogIngestor
from tarmo_vuln_core.models import Severity

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.unit
class TestTrufflehogIngestor:
    def setup_method(self) -> None:
        self.ingestor = TrufflehogIngestor()

    # -- can_handle() tests ------------------------------------------------------

    def test_can_handle_trufflehog_jsonl(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "trufflehog_sample.jsonl") is True

    def test_cannot_handle_gitleaks_json(self) -> None:
        assert self.ingestor.can_handle(FIXTURES / "gitleaks_sample.json") is False

    def test_cannot_handle_nonexistent(self, tmp_path: Path) -> None:
        assert self.ingestor.can_handle(tmp_path / "nonexistent.jsonl") is False

    def test_cannot_handle_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        assert self.ingestor.can_handle(f) is False

    # -- ingest() error tests ----------------------------------------------------

    def test_ingest_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IngestorError, match="File not found"):
            self.ingestor.ingest(tmp_path / "nonexistent.jsonl")

    # -- Finding correctness tests -----------------------------------------------

    def test_finding_count_grouped_by_detector(self) -> None:
        """3 lines with 3 DetectorNames → 3 findings."""
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert len(findings) == 3

    def test_source_tool_is_trufflehog(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert all(f.source_tool == "trufflehog" for f in findings)

    def test_id_prefix_is_trufflehog(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        assert all(f.id.startswith("trufflehog-") for f in findings)

    def test_verified_aws_is_critical(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["AWS"].severity == Severity.CRITICAL

    def test_unverified_privatekey_is_high(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["PrivateKey"].severity == Severity.HIGH

    def test_verified_stripe_is_critical(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        assert by_ref["Stripe"].severity == Severity.CRITICAL

    def test_raw_ref_is_detector_name(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        refs = {f.raw_ref for f in findings}
        assert refs == {"AWS", "PrivateKey", "Stripe"}

    def test_source_code_ref_from_git_source(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        aws = by_ref["AWS"]
        assert len(aws.source_code_refs) == 1
        ref = aws.source_code_refs[0]
        assert ref.file_path == "src/config.py"
        assert ref.start_line == 15
        assert ref.commit_sha == "abc123"
        assert "github.com" in ref.repository

    def test_source_code_ref_from_filesystem_source(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        stripe = by_ref["Stripe"]
        assert len(stripe.source_code_refs) == 1
        assert stripe.source_code_refs[0].file_path == "deploy/.env"

    def test_no_raw_secret_in_description(self) -> None:
        """Verify Raw/RawV2 values never appear in findings."""
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        for f in findings:
            # Should not contain "Raw" field values
            assert "BEGIN RSA" not in f.description
            assert "sk_live_" not in f.description

    def test_title_includes_verified_status(self) -> None:
        findings = self.ingestor.ingest(FIXTURES / "trufflehog_sample.jsonl")
        by_ref = {f.raw_ref: f for f in findings}
        assert "Verified" in by_ref["AWS"].title
        assert "Unverified" in by_ref["PrivateKey"].title
