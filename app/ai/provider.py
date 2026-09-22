"""LLM provider abstraction layer (spec §4).

Three providers share one interface: ``analyze(prompt) -> str``, plus a
``probe()`` health check used by the AI dashboard. The platform never depends
on a specific vendor and always keeps working when the AI is unavailable.

Providers:
    DisabledProvider         - deterministic no-op (used when ai_provider is off)
    OllamaProvider           - local Ollama (http://host:11434, /api/generate)
    OpenAICompatibleProvider - any OpenAI-compatible endpoint (v1/chat/completions)
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger("secureops.ai.provider")


class AIProviderError(RuntimeError):
    """Raised for provider connectivity/auth/parse failures."""


class AIProvider(ABC):
    """Provider interface. Deterministic callers treat any exception as
    'AI unavailable' and continue without AI."""

    name: str = "abstract"

    @abstractmethod
    async def analyze(self, prompt: str) -> str:
        """Return raw model text for a prompt."""

    async def probe(self) -> tuple[bool, str]:
        """Cheap availability probe (connects but does not run inference)."""
        return True, ""


def _unwrap_json_object(raw: str) -> dict[str, Any]:
    import json
    import re

    raw = raw.strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # Tolerate ```json fences and prose around the object.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    start = raw.find("{")
    if start != -1:
        end = raw.rfind("}")
        if end > start:
            try:
                return json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                pass
    raise AIProviderError("Model output was not valid JSON.")


class DisabledProvider(AIProvider):
    name = "disabled"

    async def analyze(self, prompt: str) -> str:
        raise AIProviderError("AI is disabled (ai_provider=disabled).")

    async def probe(self) -> tuple[bool, str]:
        return False, "disabled"


class OllamaProvider(AIProvider):
    name = "ollama"

    def __init__(self) -> None:
        self.base_url = (settings.ai_base_url or "http://localhost:11434").rstrip("/")
        self.model = settings.ai_model

    async def probe(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200, f"ollama {resp.status_code}"
        except httpx.HTTPError as exc:
            return False, f"ollama unreachable ({exc.__class__.__name__})"

    async def analyze(self, prompt: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": settings.ai_temperature,
                            "num_predict": settings.ai_max_tokens,
                        },
                    },
                )
        except httpx.HTTPError as exc:
            raise AIProviderError(f"Ollama request failed: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise AIProviderError(f"Ollama returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise AIProviderError("Ollama returned non-JSON.") from exc
        text = data.get("response") or data.get("message") or ""
        if not text:
            raise AIProviderError("Ollama returned an empty response.")
        return text


class OpenAICompatibleProvider(AIProvider):
    name = "openai_compatible"

    def __init__(self) -> None:
        self.base_url = (settings.ai_base_url or "http://localhost:8080").rstrip("/")
        self.model = settings.ai_model
        self.api_key = settings.ai_api_key

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def probe(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/v1/models", headers=self._headers())
                return resp.status_code in (200, 401, 403), f"endpoint {resp.status_code}"
        except httpx.HTTPError as exc:
            return False, f"endpoint unreachable ({exc.__class__.__name__})"

    async def analyze(self, prompt: str) -> str:
        # System/user split document the instruction boundary (spec §31).
        sys_ix = prompt.find("<<<SYSTEM>>>")
        if sys_ix != -1:
            end = prompt.find("<<</SYSTEM>>>")
            system = prompt[sys_ix + len("<<<SYSTEM>>>") : end].strip() if end != -1 else ""
            user = (prompt[:sys_ix] + prompt[end + len("<<</SYSTEM>>>") :]).strip()
        else:
            system, user = "", prompt

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": user})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": settings.ai_temperature,
            "max_tokens": settings.ai_max_tokens,
        }
        try:
            async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
                resp = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload,
                    headers=self._headers(),
                )
        except httpx.HTTPError as exc:
            raise AIProviderError(f"Provider request failed: {exc.__class__.__name__}") from exc
        if resp.status_code != 200:
            raise AIProviderError(f"Provider returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise AIProviderError("Provider returned non-JSON.") from exc
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError("Provider response missing choices.") from exc
        if not text:
            raise AIProviderError("Provider returned an empty response.")
        return text


def get_provider() -> AIProvider:
    """Instantiate the configured provider (spec §4: no hard-coded vendor)."""
    kind = (settings.ai_provider or "disabled").lower()
    if kind == "ollama":
        return OllamaProvider()
    if kind in ("openai_compatible", "openai", "localai"):
        return OpenAICompatibleProvider()
    return DisabledProvider()
