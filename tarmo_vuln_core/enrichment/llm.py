"""LLM enrichment — generates contextual finding prose via an OpenAI-compatible API.

Supports any OpenAI-compatible endpoint: OpenAI, Azure OpenAI, Anthropic
(via the compatibility endpoint), and local models via Ollama or LM Studio.

Install the optional dependency before use:
    pip install 'tarmo-vuln-core[llm]'
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel

if TYPE_CHECKING:
    import httpx
else:
    try:
        import httpx
    except ImportError:  # httpx is part of the [llm] extra
        httpx = None  # type: ignore[assignment]

from tarmo_vuln_core.models import Finding

logger = logging.getLogger(__name__)

LLMProfile = Literal["local", "claude", "auto"]


# ── Local server health probe ────────────────────────────────────────────────


def local_server_healthy(endpoint: str, *, timeout: float = 0.5) -> bool:
    """Probe an OpenAI-compatible endpoint's /health route.

    Strips any path component (e.g. ``/v1``) and queries ``<scheme>://<host>/health``.
    Returns True only on a 2xx response. Returns False if httpx is not installed.
    """
    if httpx is None:
        return False
    try:
        parsed = urlparse(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return False
        health_url = urlunparse((parsed.scheme, parsed.netloc, "/health", "", "", ""))
        resp = httpx.get(health_url, timeout=timeout)
        return 200 <= resp.status_code < 300
    except Exception:  # noqa: BLE001 — health probe must never raise
        return False


# ── LLM config ──────────────────────────────────────────────────────────────


class LLMConfig(BaseModel):
    """LLM provider configuration for AI-powered finding enrichment.

    Config resolution order (first wins): CLI flags → engagement.yaml [llm] block
    → TARMO_LLM_* environment variables → PENTEST_SCRIBE_LLM_* (backward compat)
    → auto policy → defaults.

    The ``profile`` field is the user-facing knob. ``provider`` is the concrete
    backend the dispatch picks once :meth:`resolve` has run.

    Sampling fields (``temperature``, ``top_p``, ``max_tokens``, ``timeout``)
    are optional. Defaults match the values previously hardcoded inside
    ``_openai_complete`` so existing callers see no behaviour change. They are
    primarily intended for tuning local OpenAI-compatible servers (llama.cpp's
    ``llama-server``, Ollama, LM Studio).
    """

    profile: LLMProfile = "auto"
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    endpoint: str | None = None  # custom base_url (Ollama, LM Studio, llama.cpp, Azure, etc.)
    api_key: str | None = None
    temperature: float = 0.3
    top_p: float | None = None  # None = do not pass the parameter to the SDK
    max_tokens: int = 512
    timeout: float | None = None  # None = use the openai SDK's built-in default

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Build an LLMConfig from TARMO_LLM_* env vars (with PENTEST_SCRIBE_LLM_* fallback)."""

        def _read(*names: str) -> str | None:
            for n in names:
                v = os.environ.get(n)
                if v is not None and v != "":
                    return v
            return None

        def _read_float(*names: str, default: float | None) -> float | None:
            v = _read(*names)
            if v is None:
                return default
            try:
                return float(v)
            except ValueError as exc:
                raise ValueError(f"Invalid float for {names[0]}: {v!r}") from exc

        def _read_int(*names: str, default: int) -> int:
            v = _read(*names)
            if v is None:
                return default
            try:
                return int(v)
            except ValueError as exc:
                raise ValueError(f"Invalid int for {names[0]}: {v!r}") from exc

        return cls(
            profile=os.environ.get("TARMO_LLM_PROFILE", "auto"),  # type: ignore[arg-type]
            provider=_read("TARMO_LLM_PROVIDER", "PENTEST_SCRIBE_LLM_PROVIDER") or "openai",
            model=_read("TARMO_LLM_MODEL", "PENTEST_SCRIBE_LLM_MODEL") or "gpt-4o-mini",
            endpoint=_read("TARMO_LLM_ENDPOINT", "PENTEST_SCRIBE_LLM_ENDPOINT"),
            api_key=_read("TARMO_LLM_API_KEY", "PENTEST_SCRIBE_LLM_API_KEY"),
            temperature=_read_float(  # type: ignore[arg-type]
                "TARMO_LLM_TEMPERATURE", "PENTEST_SCRIBE_LLM_TEMPERATURE", default=0.3
            ),
            top_p=_read_float("TARMO_LLM_TOP_P", "PENTEST_SCRIBE_LLM_TOP_P", default=None),
            max_tokens=_read_int(
                "TARMO_LLM_MAX_TOKENS", "PENTEST_SCRIBE_LLM_MAX_TOKENS", default=512
            ),
            timeout=_read_float("TARMO_LLM_TIMEOUT", "PENTEST_SCRIBE_LLM_TIMEOUT", default=None),
        )

    def resolve(self, *, tool: str | None = None) -> LLMConfig:
        """Apply the auto policy and return a config with concrete provider/profile.

        Auto policy (explicit, never env-sniffing):
          - if ``tool == "storm"``                  → claude (anthropic)
          - else if local server is healthy         → local (openai-compat)
          - else                                    → claude (anthropic)
        """
        prof: LLMProfile = self.profile
        if prof == "auto":
            if tool == "storm":
                prof = "claude"
            elif self.endpoint and local_server_healthy(self.endpoint):
                prof = "local"
            else:
                prof = "claude"

        if prof == "local":
            return self.model_copy(update={"profile": "local", "provider": "openai"})
        # claude
        return self.model_copy(update={"profile": "claude", "provider": "anthropic"})

    def complete(self, system: str, user: str) -> str:
        """Dispatch a chat completion to the configured provider."""
        logger.info(
            "LLM dispatch provider=%s profile=%s model=%s",
            self.provider,
            self.profile,
            self.model,
        )
        if self.provider == "anthropic":
            return _anthropic_complete(self, system, user)
        return _openai_complete(self, system, user)


# ── Prompt templates ──────────────────────────────────────────────────────────

_FIELD_SYSTEM_PROMPT = (
    "You are a senior penetration tester writing a professional security assessment report. "
    "Your prose is precise, contextual, and client-ready. "
    "Never include markdown headers, bullet-point markers (unless explicitly asked), "
    "or placeholder text like '[host]' or '[insert here]'."
)

_FIELD_INSTRUCTIONS: dict[str, str] = {
    "description": (
        "Write a 2-3 sentence technical description of the vulnerability. "
        "Mention the specific affected hosts and services to make it contextual. "
        "Professional pentest report style. Output only the description text."
    ),
    "impact": (
        "Write a 2-3 sentence impact statement covering both technical and business risk. "
        "Reference the specific affected hosts and scope. "
        "Output only the impact text."
    ),
    "remediation": (
        "Write specific, actionable remediation guidance with 3-5 concrete steps. "
        "Reference the technology stack implied by the affected hosts when relevant. "
        "Output only the remediation text."
    ),
    "steps": (
        "Write 3-5 reproduction steps for verifying this vulnerability. "
        "Return each step on its own line starting with '1.', '2.', etc. "
        "Output only the numbered steps."
    ),
}

_DEFAULT_FIELDS = ["description", "impact", "remediation"]


# ── Context builder ───────────────────────────────────────────────────────────


def _build_finding_context(finding: Finding) -> str:
    """Format a finding's metadata as a context block for the LLM prompt."""
    hosts = ", ".join(finding.affected_hosts[:10]) or "unspecified"
    parts = [
        f"Title: {finding.title}",
        f"Severity: {finding.severity.value}",
        f"Source tool: {finding.source_tool}",
        f"Affected hosts/services: {hosts}",
    ]
    if finding.cvss_score is not None:
        parts.append(f"CVSS score: {finding.cvss_score}")
    if finding.cvss_vector:
        parts.append(f"CVSS vector: {finding.cvss_vector}")
    if finding.cwe_id:
        parts.append(f"CWE: CWE-{finding.cwe_id}")
    if finding.owasp_id:
        parts.append(f"OWASP: {finding.owasp_id}")
    if finding.raw_ref:
        parts.append(f"Reference: {finding.raw_ref}")
    # Include existing terse description as seed text for the LLM
    if finding.description:
        parts.append(f"\nCurrent description (seed text): {finding.description[:500]}")
    return "\n".join(parts)


# ── LLM call ─────────────────────────────────────────────────────────────────

# Single retry on transient failures (network blips, 5xx, anthropic 529).
# Two attempts total — beyond that, escalate to the caller. ImportError is
# never retried because the missing package will not appear mid-loop.
_MAX_ATTEMPTS = 2
_RETRY_BACKOFF_SECONDS = 1.0


def _retry(label: str, fn: Callable[[], str]) -> str:
    """Run ``fn`` up to ``_MAX_ATTEMPTS`` times, swallowing ImportError out of the loop."""
    import time

    last_exc: Exception | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            return fn()
        except ImportError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.warning("%s attempt %d/%d failed: %s", label, attempt, _MAX_ATTEMPTS, exc)
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_RETRY_BACKOFF_SECONDS)
    assert last_exc is not None
    raise last_exc


def _openai_complete(config: LLMConfig, system: str, user: str) -> str:
    """Call an OpenAI-compatible API (OpenAI, llama.cpp, Ollama, LM Studio…)."""
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise ImportError(
            "LLM enrichment requires the 'openai' package. "
            "Install it with: pip install 'tarmo-vuln-core[llm]'"
        ) from exc

    client_kwargs: dict = {"api_key": config.api_key or "dummy"}  # type: ignore[type-arg]
    if config.endpoint:
        client_kwargs["base_url"] = config.endpoint
    if config.timeout is not None:
        client_kwargs["timeout"] = config.timeout

    completion_kwargs: dict = {  # type: ignore[type-arg]
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
    }
    if config.top_p is not None:
        completion_kwargs["top_p"] = config.top_p

    def _do_call() -> str:
        client = OpenAI(**client_kwargs)
        response = client.chat.completions.create(**completion_kwargs)
        return response.choices[0].message.content or ""

    return _retry("openai", _do_call)


def _anthropic_complete(config: LLMConfig, system: str, user: str) -> str:
    """Call the Anthropic Messages API directly."""
    try:
        import anthropic
    except ImportError as exc:
        raise ImportError(
            "LLM enrichment with provider='anthropic' requires the 'anthropic' package. "
            "Install it with: pip install 'tarmo-vuln-core[anthropic]'"
        ) from exc

    def _do_call() -> str:
        client = (
            anthropic.Anthropic(api_key=config.api_key) if config.api_key else anthropic.Anthropic()
        )
        msg = client.messages.create(
            model=config.model,
            max_tokens=config.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts: list[str] = []
        for block in msg.content:
            if getattr(block, "type", None) == "text":
                parts.append(getattr(block, "text", ""))
        return "".join(parts)

    return _retry("anthropic", _do_call)


def _call_llm(prompt: str, system: str, config: LLMConfig) -> str:
    """Backward-compat shim — dispatches via :meth:`LLMConfig.complete`.

    Existing callers (and tests) patch this function, so it's preserved as the
    single entry point used by :func:`enrich_finding_from_llm`.
    """
    return config.complete(system, prompt)


# ── Steps parser ──────────────────────────────────────────────────────────────


def _parse_steps(text: str) -> list[str]:
    """Parse a numbered-list LLM response into a plain list of step strings."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    steps = []
    for line in lines:
        cleaned = re.sub(r"^\d+[\.\)]\s*", "", line)
        if cleaned:
            steps.append(cleaned)
    return steps


# ── Public API ────────────────────────────────────────────────────────────────


def enrich_finding_from_llm(
    finding: Finding,
    config: LLMConfig,
    *,
    fields: list[str] | None = None,
    force: bool = False,
) -> Finding:
    """Enrich a single finding with AI-generated contextual prose.

    By default enriches ``description``, ``impact``, and ``remediation``.
    Skips fields that are already populated unless ``force=True``.

    Args:
        finding: The finding to enrich.
        config: LLM provider configuration.
        fields: Fields to enrich. Defaults to ["description", "impact", "remediation"].
        force: If True, regenerate even if the field is already populated.

    Returns:
        Enriched Finding (or original if the API call fails).

    Raises:
        ImportError: If the ``openai`` package is not installed (propagated from first call).
    """
    resolved_fields = fields if fields is not None else _DEFAULT_FIELDS
    context = _build_finding_context(finding)
    updates: dict = {}  # type: ignore[type-arg]
    import_error_raised = False

    for field in resolved_fields:
        if field not in _FIELD_INSTRUCTIONS:
            logger.warning("Unknown LLM field '%s'; skipping", field)
            continue

        existing = getattr(finding, field, None)
        already_populated = (
            bool(existing) if field == "steps" else bool(str(existing or "").strip())
        )

        if already_populated and not force:
            logger.debug("Skipping '%s' for %s — already populated", field, finding.id)
            continue

        instruction = _FIELD_INSTRUCTIONS[field]
        user_prompt = f"{context}\n\nTask: {instruction}"
        try:
            text = _call_llm(user_prompt, _FIELD_SYSTEM_PROMPT, config)
            if field == "steps":
                updates[field] = _parse_steps(text)
            else:
                updates[field] = text.strip()
            logger.info("LLM enriched field '%s' for finding '%s'", field, finding.id)
        except ImportError:
            if not import_error_raised:
                import_error_raised = True
                raise  # propagate ImportError immediately
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM enrichment failed for '%s.%s': %s", finding.id, field, exc)

    if not updates:
        return finding
    return finding.model_copy(update=updates)


def enrich_findings_from_llm(
    findings: list[Finding],
    config: LLMConfig,
    *,
    finding_id: str | None = None,
    fields: list[str] | None = None,
    force: bool = False,
) -> list[Finding]:
    """Enrich a list of findings with AI-generated contextual prose.

    Args:
        findings: Findings to enrich.
        config: LLM provider configuration.
        finding_id: If set, only enrich the finding with this slug; others pass through.
        fields: Fields to enrich (default: description, impact, remediation).
        force: Regenerate even if fields are already populated.

    Returns:
        List of enriched findings (order preserved).
    """
    result = []
    for f in findings:
        if finding_id and f.id != finding_id:
            result.append(f)
            continue
        result.append(enrich_finding_from_llm(f, config, fields=fields, force=force))
    return result
