"""Tests for shared attack path, exploit metadata, and credential models (TDD — written FIRST)."""

from __future__ import annotations

import pytest

# ── 1. AttackStep ────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAttackStep:
    def test_create_step(self) -> None:
        from tarmo_vuln_core.models.attack_path import AttackStep

        step = AttackStep(
            source_host="10.0.0.1",
            target_host="10.0.1.1",
            technique="T1021.002",
            tactic="Lateral Movement",
            tool_used="psexec",
        )
        assert step.source_host == "10.0.0.1"
        assert step.technique == "T1021.002"
        assert step.success is True

    def test_step_with_credential(self) -> None:
        from tarmo_vuln_core.models.attack_path import AttackStep

        step = AttackStep(
            source_host="10.0.0.1",
            target_host="10.0.1.1",
            technique="T1078",
            tactic="Defense Evasion",
            tool_used="ssh",
            credential_used="admin-ntlm-hash",
        )
        assert step.credential_used == "admin-ntlm-hash"


# ── 2. AttackPath ────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestAttackPath:
    def test_create_path(self) -> None:
        from tarmo_vuln_core.models.attack_path import AttackPath, AttackStep

        path = AttackPath(
            id="ext-to-da",
            name="External to Domain Admin",
            objective="Achieve Domain Admin",
            steps=[
                AttackStep(
                    source_host="attacker",
                    target_host="web01",
                    technique="T1190",
                    tactic="Initial Access",
                    tool_used="exploit/multi/http/log4shell",
                ),
                AttackStep(
                    source_host="web01",
                    target_host="dc01",
                    technique="T1021.002",
                    tactic="Lateral Movement",
                    tool_used="psexec",
                ),
            ],
        )
        assert path.id == "ext-to-da"
        assert len(path.steps) == 2
        assert path.steps[0].tactic == "Initial Access"
        assert path.steps[1].tactic == "Lateral Movement"

    def test_path_json_roundtrip(self) -> None:
        from tarmo_vuln_core.models.attack_path import AttackPath, AttackStep

        path = AttackPath(
            id="test",
            name="Test Path",
            objective="Test",
            steps=[
                AttackStep(
                    source_host="a",
                    target_host="b",
                    technique="T1190",
                    tactic="Initial Access",
                    tool_used="nmap",
                )
            ],
        )
        data = path.model_dump(mode="json")
        restored = AttackPath(**data)
        assert restored.id == "test"
        assert restored.steps[0].technique == "T1190"


# ── 3. ExploitMetadata ──────────────────────────────────────────────────────


@pytest.mark.unit
class TestExploitMetadata:
    def test_create_metadata(self) -> None:
        from tarmo_vuln_core.models.attack_path import SharedExploitMetadata

        meta = SharedExploitMetadata(
            id="log4shell",
            name="Log4Shell RCE",
            cve="CVE-2021-44228",
            cwe_id=502,
            msf_module="exploit/multi/http/log4shell_header_injection",
            risk_level="critical",
        )
        assert meta.cve == "CVE-2021-44228"
        assert meta.msf_module == "exploit/multi/http/log4shell_header_injection"

    def test_metadata_defaults(self) -> None:
        from tarmo_vuln_core.models.attack_path import SharedExploitMetadata

        meta = SharedExploitMetadata(id="test", name="Test")
        assert meta.cve is None
        assert meta.risk_level == "moderate"


# ── 4. SharedCredential ─────────────────────────────────────────────────────


@pytest.mark.unit
class TestSharedCredential:
    def test_create_credential(self) -> None:
        from tarmo_vuln_core.models.attack_path import SharedCredential

        cred = SharedCredential(
            id="admin-ntlm",
            username="Administrator",
            domain="CORP.LOCAL",
            credential_type="ntlm_hash",
            value="aad3b435:31d6cfe0",
            source_host="10.0.0.5",
            source_method="sam_dump",
        )
        assert cred.username == "Administrator"
        assert cred.credential_type == "ntlm_hash"
        assert cred.source_method == "sam_dump"

    def test_credential_with_validation(self) -> None:
        from tarmo_vuln_core.models.attack_path import SharedCredential

        cred = SharedCredential(
            id="admin-pass",
            username="admin",
            credential_type="plaintext",
            value="P@ssw0rd",
            validated_hosts=["10.0.0.1", "10.0.0.2"],
        )
        assert len(cred.validated_hosts) == 2

    def test_credential_json_roundtrip(self) -> None:
        from tarmo_vuln_core.models.attack_path import SharedCredential

        cred = SharedCredential(
            id="test",
            username="user",
            credential_type="ssh_key",
            value="ssh-rsa AAAA...",
            source_host="10.0.0.1",
            validated_hosts=["10.0.0.2"],
        )
        data = cred.model_dump(mode="json")
        restored = SharedCredential(**data)
        assert restored.credential_type == "ssh_key"
        assert restored.validated_hosts == ["10.0.0.2"]


# ── 5. Exports ───────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestModelExports:
    def test_importable_from_models_package(self) -> None:
        from tarmo_vuln_core.models import (
            AttackPath,
            AttackStep,
            SharedCredential,
            SharedExploitMetadata,
        )

        assert AttackPath is not None
        assert AttackStep is not None
        assert SharedExploitMetadata is not None
        assert SharedCredential is not None
