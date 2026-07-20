"""Tests for LLMConfig profile resolution and provider dispatch.

Strict TDD: this file should be RED before the implementation lands.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tarmo_vuln_core.enrichment.llm import LLMConfig

# ── profile field ────────────────────────────────────────────────────────────


class TestProfileField:
    def test_profile_default_is_auto(self) -> None:
        config = LLMConfig()
        assert config.profile == "auto"

    def test_profile_accepts_local(self) -> None:
        config = LLMConfig(profile="local")
        assert config.profile == "local"

    def test_profile_accepts_claude(self) -> None:
        config = LLMConfig(profile="claude")
        assert config.profile == "claude"

    def test_profile_rejects_unknown(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            LLMConfig(profile="garbage")  # type: ignore[arg-type]


# ── from_env reads profile ───────────────────────────────────────────────────


class TestFromEnvProfile:
    def test_from_env_reads_profile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_LLM_PROFILE", "local")
        config = LLMConfig.from_env()
        assert config.profile == "local"

    def test_from_env_default_profile_is_auto(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TARMO_LLM_PROFILE", raising=False)
        config = LLMConfig.from_env()
        assert config.profile == "auto"


# ── local server health probe ────────────────────────────────────────────────


class TestLocalServerHealthy:
    def test_healthy_when_endpoint_returns_2xx(self) -> None:
        from tarmo_vuln_core.enrichment.llm import local_server_healthy

        mock_resp = MagicMock(status_code=200)
        with patch("tarmo_vuln_core.enrichment.llm.httpx.get", return_value=mock_resp) as mock_get:
            assert local_server_healthy("http://127.0.0.1:8081/v1") is True
        mock_get.assert_called_once()
        # Health URL should target /health on the server root, not /v1/health
        called_url = mock_get.call_args[0][0]
        assert "health" in called_url

    def test_unhealthy_on_timeout(self) -> None:
        import httpx

        from tarmo_vuln_core.enrichment.llm import local_server_healthy

        with patch(
            "tarmo_vuln_core.enrichment.llm.httpx.get",
            side_effect=httpx.ConnectError("nope"),
        ):
            assert local_server_healthy("http://127.0.0.1:8081/v1") is False

    def test_unhealthy_on_5xx(self) -> None:
        from tarmo_vuln_core.enrichment.llm import local_server_healthy

        mock_resp = MagicMock(status_code=503)
        with patch("tarmo_vuln_core.enrichment.llm.httpx.get", return_value=mock_resp):
            assert local_server_healthy("http://127.0.0.1:8081/v1") is False


# ── resolve(): explicit auto policy rules ────────────────────────────────────


class TestResolveAutoPolicy:
    def test_storm_tool_always_routes_to_claude_even_when_local_healthy(self) -> None:
        config = LLMConfig(profile="auto", endpoint="http://127.0.0.1:8081/v1")
        with patch("tarmo_vuln_core.enrichment.llm.local_server_healthy", return_value=True):
            resolved = config.resolve(tool="storm")
        assert resolved.provider == "anthropic"

    def test_scribe_with_healthy_local_routes_to_local(self) -> None:
        config = LLMConfig(profile="auto", endpoint="http://127.0.0.1:8081/v1")
        with patch("tarmo_vuln_core.enrichment.llm.local_server_healthy", return_value=True):
            resolved = config.resolve(tool="scribe")
        assert resolved.provider == "openai"

    def test_scribe_with_unhealthy_local_falls_back_to_claude(self) -> None:
        config = LLMConfig(profile="auto", endpoint="http://127.0.0.1:8081/v1")
        with patch("tarmo_vuln_core.enrichment.llm.local_server_healthy", return_value=False):
            resolved = config.resolve(tool="scribe")
        assert resolved.provider == "anthropic"

    def test_explicit_local_profile_skips_health_check(self) -> None:
        config = LLMConfig(profile="local", endpoint="http://127.0.0.1:8081/v1")
        with patch(
            "tarmo_vuln_core.enrichment.llm.local_server_healthy", return_value=False
        ) as mock_health:
            resolved = config.resolve(tool="scribe")
        assert resolved.provider == "openai"
        mock_health.assert_not_called()

    def test_explicit_claude_profile_routes_to_anthropic(self) -> None:
        config = LLMConfig(profile="claude")
        resolved = config.resolve(tool="scribe")
        assert resolved.provider == "anthropic"

    def test_resolved_profile_is_concrete_not_auto(self) -> None:
        config = LLMConfig(profile="auto", endpoint="http://127.0.0.1:8081/v1")
        with patch("tarmo_vuln_core.enrichment.llm.local_server_healthy", return_value=True):
            resolved = config.resolve(tool="scribe")
        assert resolved.profile in ("local", "claude")


# ── complete() dispatch on provider ──────────────────────────────────────────


class TestCompleteDispatch:
    def test_openai_provider_uses_openai_helper(self) -> None:
        config = LLMConfig(provider="openai", model="gpt-4o-mini")
        with (
            patch(
                "tarmo_vuln_core.enrichment.llm._openai_complete",
                return_value="oai-response",
            ) as mock_oai,
            patch(
                "tarmo_vuln_core.enrichment.llm._anthropic_complete",
                return_value="anth-response",
            ) as mock_anth,
        ):
            text = config.complete("system", "user")
        assert text == "oai-response"
        mock_oai.assert_called_once()
        mock_anth.assert_not_called()

    def test_anthropic_provider_uses_anthropic_helper(self) -> None:
        config = LLMConfig(provider="anthropic", model="claude-sonnet-4-6")
        with (
            patch(
                "tarmo_vuln_core.enrichment.llm._openai_complete",
                return_value="oai-response",
            ) as mock_oai,
            patch(
                "tarmo_vuln_core.enrichment.llm._anthropic_complete",
                return_value="anth-response",
            ) as mock_anth,
        ):
            text = config.complete("system", "user")
        assert text == "anth-response"
        mock_anth.assert_called_once()
        mock_oai.assert_not_called()

    def test_complete_logs_dispatch_telemetry(self, caplog: pytest.LogCaptureFixture) -> None:
        """complete() must emit a single INFO log line naming provider/profile/model."""
        import logging

        config = LLMConfig(provider="openai", profile="local", model="qwen3.5-35b-a3b")
        with (
            patch(
                "tarmo_vuln_core.enrichment.llm._openai_complete",
                return_value="ok",
            ),
            caplog.at_level(logging.INFO, logger="tarmo_vuln_core.enrichment.llm"),
        ):
            config.complete("s", "u")
        dispatch_logs = [r for r in caplog.records if "dispatch" in r.getMessage().lower()]
        assert len(dispatch_logs) == 1
        msg = dispatch_logs[0].getMessage()
        assert "openai" in msg
        assert "local" in msg
        assert "qwen3.5-35b-a3b" in msg


# ── retry on transient failures ──────────────────────────────────────────────


class TestRetry:
    def test_openai_retries_once_on_transient_error(self) -> None:
        """One transient failure should be retried; second-try success returned."""
        from tarmo_vuln_core.enrichment.llm import _openai_complete

        attempts = {"n": 0}

        class _FakeResp:
            class _Choice:
                class _Msg:
                    content = "second-try-ok"

                message = _Msg()

            choices = [_Choice()]

        class _FakeClient:
            def __init__(self, **_: object) -> None:
                self.chat = self

            @property
            def completions(self) -> _FakeClient:  # type: ignore[name-defined]
                return self

            def create(self, **_: object) -> _FakeResp:
                attempts["n"] += 1
                if attempts["n"] == 1:
                    raise RuntimeError("transient 503")
                return _FakeResp()

        with patch("openai.OpenAI", _FakeClient):
            text = _openai_complete(
                LLMConfig(provider="openai", model="m", endpoint="http://x/v1"),
                "s",
                "u",
            )
        assert text == "second-try-ok"
        assert attempts["n"] == 2

    def test_openai_raises_after_two_failures(self) -> None:
        """Two consecutive failures must propagate the original error."""
        from tarmo_vuln_core.enrichment.llm import _openai_complete

        class _FailingClient:
            def __init__(self, **_: object) -> None:
                self.chat = self

            @property
            def completions(self) -> _FailingClient:  # type: ignore[name-defined]
                return self

            def create(self, **_: object) -> object:
                raise RuntimeError("still down")

        with (
            patch("openai.OpenAI", _FailingClient),
            pytest.raises(RuntimeError, match="still down"),
        ):
            _openai_complete(
                LLMConfig(provider="openai", model="m", endpoint="http://x/v1"),
                "s",
                "u",
            )


# ── Sampling parameters (local-LLM support) ───────────────────────────────────


class TestSamplingParameterDefaults:
    """Defaults must match the values previously hardcoded in _openai_complete
    so existing callers see no behaviour change."""

    def test_default_temperature_is_legacy_value(self) -> None:
        assert LLMConfig().temperature == 0.3

    def test_default_max_tokens_is_legacy_value(self) -> None:
        assert LLMConfig().max_tokens == 512

    def test_default_top_p_is_none(self) -> None:
        # None means: do not pass the parameter to the SDK at all.
        assert LLMConfig().top_p is None

    def test_default_timeout_is_none(self) -> None:
        # None means: defer to the openai SDK's built-in default.
        assert LLMConfig().timeout is None

    def test_explicit_overrides_round_trip(self) -> None:
        cfg = LLMConfig(temperature=0.2, top_p=0.9, max_tokens=1024, timeout=120.0)
        assert cfg.temperature == 0.2
        assert cfg.top_p == 0.9
        assert cfg.max_tokens == 1024
        assert cfg.timeout == 120.0


class TestFromEnvSamplingParams:
    def test_from_env_reads_tarmo_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_LLM_TEMPERATURE", "0.2")
        monkeypatch.setenv("TARMO_LLM_TOP_P", "0.9")
        monkeypatch.setenv("TARMO_LLM_MAX_TOKENS", "768")
        monkeypatch.setenv("TARMO_LLM_TIMEOUT", "90")
        cfg = LLMConfig.from_env()
        assert cfg.temperature == 0.2
        assert cfg.top_p == 0.9
        assert cfg.max_tokens == 768
        assert cfg.timeout == 90.0

    def test_from_env_falls_back_to_pentest_scribe_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TARMO_LLM_TEMPERATURE", raising=False)
        monkeypatch.setenv("PENTEST_SCRIBE_LLM_TEMPERATURE", "0.15")
        cfg = LLMConfig.from_env()
        assert cfg.temperature == 0.15

    def test_from_env_unset_keeps_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "TARMO_LLM_TEMPERATURE",
            "TARMO_LLM_TOP_P",
            "TARMO_LLM_MAX_TOKENS",
            "TARMO_LLM_TIMEOUT",
            "PENTEST_SCRIBE_LLM_TEMPERATURE",
            "PENTEST_SCRIBE_LLM_TOP_P",
            "PENTEST_SCRIBE_LLM_MAX_TOKENS",
            "PENTEST_SCRIBE_LLM_TIMEOUT",
        ):
            monkeypatch.delenv(var, raising=False)
        cfg = LLMConfig.from_env()
        assert cfg.temperature == 0.3
        assert cfg.max_tokens == 512
        assert cfg.top_p is None
        assert cfg.timeout is None

    def test_from_env_invalid_float_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARMO_LLM_TEMPERATURE", "not-a-float")
        with pytest.raises(ValueError, match="TARMO_LLM_TEMPERATURE"):
            LLMConfig.from_env()


class TestOpenAICompletePassesSamplingParams:
    """The OpenAI client call must receive temperature/max_tokens/top_p from config."""

    def test_passes_temperature_max_tokens_top_p_and_timeout(self) -> None:
        from tarmo_vuln_core.enrichment.llm import _openai_complete

        cfg = LLMConfig(
            provider="openai",
            endpoint="http://127.0.0.1:8000/v1",
            model="granite-4.0-h-tiny",
            api_key="local",
            temperature=0.2,
            top_p=0.9,
            max_tokens=1024,
            timeout=120.0,
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client) as mock_ctor:
            text = _openai_complete(cfg, "sys", "user")

        assert text == "ok"
        ctor_kwargs = mock_ctor.call_args.kwargs
        assert ctor_kwargs["base_url"] == "http://127.0.0.1:8000/v1"
        assert ctor_kwargs["api_key"] == "local"
        assert ctor_kwargs["timeout"] == 120.0

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["model"] == "granite-4.0-h-tiny"
        assert call_kwargs["temperature"] == 0.2
        assert call_kwargs["max_tokens"] == 1024
        assert call_kwargs["top_p"] == 0.9

    def test_omits_top_p_when_unset(self) -> None:
        """top_p=None means the parameter must not appear in the request kwargs."""
        from tarmo_vuln_core.enrichment.llm import _openai_complete

        cfg = LLMConfig(provider="openai", endpoint="http://x/v1", model="m", api_key="k")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client) as mock_ctor:
            _openai_complete(cfg, "sys", "user")

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert "top_p" not in call_kwargs
        # timeout=None must NOT be passed to the OpenAI ctor either; the SDK
        # treats explicit None as "no timeout" which is wrong.
        assert "timeout" not in mock_ctor.call_args.kwargs


class TestAnthropicCompleteUsesMaxTokens:
    def test_anthropic_call_uses_config_max_tokens(self) -> None:
        from tarmo_vuln_core.enrichment.llm import _anthropic_complete

        cfg = LLMConfig(
            provider="anthropic",
            model="claude-sonnet-4-6",
            api_key="anth-key",
            max_tokens=2048,
        )

        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "hi"
        mock_msg = MagicMock(content=[mock_block])
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_msg

        with patch("anthropic.Anthropic", return_value=mock_client):
            text = _anthropic_complete(cfg, "sys", "user")

        assert text == "hi"
        call_kwargs = mock_client.messages.create.call_args.kwargs
        assert call_kwargs["max_tokens"] == 2048
