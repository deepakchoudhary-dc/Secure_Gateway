"""
Google Gemini LLM provider adapter.

Supports Google Gemini models via Gemini native v1beta REST API or OpenAI-compatible endpoint.
"""

import logging
import time
from typing import Any, Dict, List, Optional
import requests

from .base import LLMMessage, LLMProvider, LLMResponse, LLMUsage, ProviderError

logger = logging.getLogger(__name__)

_NON_RETRYABLE_STATUS = {400, 401, 403, 422}


class GeminiProvider(LLMProvider):
    """Adapter for Google Gemini API."""

    def __init__(self, base_url: str = "", api_key: str = "", default_model: str = "gemini-2.0-flash"):
        self._base_url = (base_url or "").strip()
        self._api_key = api_key.strip()
        self._default_model = default_model or "gemini-2.0-flash"
        self._session = requests.Session()

    @property
    def name(self) -> str:
        return "gemini"

    def complete(
        self,
        messages: List[LLMMessage],
        model: str = "",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        timeout: float = 30.0,
    ) -> LLMResponse:
        target_model = (model or self._default_model).replace("models/", "")
        
        if self._base_url and "openai" in self._base_url:
            return self._complete_openai_compat(messages, target_model, temperature, max_tokens, timeout)
            
        return self._complete_native_gemini(messages, target_model, temperature, max_tokens, timeout)

    def _complete_openai_compat(
        self,
        messages: List[LLMMessage],
        model: str,
        temperature: float,
        max_tokens: Optional[int],
        timeout: float,
    ) -> LLMResponse:
        url = self._base_url or "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        start = time.monotonic()
        try:
            resp = self._session.post(url, headers=headers, json=payload, timeout=timeout, allow_redirects=True)
        except requests.exceptions.Timeout as exc:
            raise ProviderError(f"Gemini request timed out after {timeout}s", retryable=True) from exc
        except requests.exceptions.ConnectionError as exc:
            raise ProviderError(f"Gemini connection failed: {exc}", retryable=True) from exc
        latency = (time.monotonic() - start) * 1000

        if resp.status_code != 200:
            retryable = resp.status_code not in _NON_RETRYABLE_STATUS
            raise ProviderError(
                f"Gemini API error {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
                retryable=retryable,
            )

        raw = resp.json()
        if "choices" in raw and raw["choices"]:
            choice = raw["choices"][0]
            content = choice.get("message", {}).get("content", "")
            usage_raw = raw.get("usage", {})
            usage = LLMUsage(
                prompt_tokens=usage_raw.get("prompt_tokens", 0),
                completion_tokens=usage_raw.get("completion_tokens", 0),
                total_tokens=usage_raw.get("total_tokens", 0),
            )
            return LLMResponse(
                content=content,
                model=raw.get("model", model),
                usage=usage,
                raw_response=raw,
                provider=self.name,
                latency_ms=latency,
            )
        raise ProviderError("Gemini response missing choices content", retryable=False)

    def _complete_native_gemini(
        self,
        messages: List[LLMMessage],
        model: str,
        temperature: float,
        max_tokens: Optional[int],
        timeout: float,
    ) -> LLMResponse:
        # Candidate model names to try if 404 is encountered
        candidate_models = [model]
        if not model.endswith("-latest"):
            candidate_models.append(f"{model}-latest")
        if "gemini-2.0-flash" not in candidate_models:
            candidate_models.append("gemini-2.0-flash")
        if "gemini-1.5-flash" not in candidate_models:
            candidate_models.append("gemini-1.5-flash")
        if "gemini-1.5-pro" not in candidate_models:
            candidate_models.append("gemini-1.5-pro")

        last_error = None
        for current_model in candidate_models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{current_model}:generateContent"
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": self._api_key,
            }
            if not self._api_key.startswith("AIza"):
                headers["Authorization"] = f"Bearer {self._api_key}"

            system_instruction = None
            contents = []

            for m in messages:
                if m.role == "system":
                    system_instruction = {"parts": [{"text": m.content}]}
                else:
                    role = "user" if m.role == "user" else "model"
                    contents.append({"role": role, "parts": [{"text": m.content}]})

            payload: Dict[str, Any] = {
                "contents": contents,
                "generationConfig": {
                    "temperature": temperature,
                }
            }
            if system_instruction:
                payload["systemInstruction"] = system_instruction
            if max_tokens is not None:
                payload["generationConfig"]["maxOutputTokens"] = max_tokens

            start = time.monotonic()
            try:
                resp = self._session.post(url, headers=headers, json=payload, timeout=timeout, allow_redirects=True)
            except requests.exceptions.Timeout as exc:
                raise ProviderError(f"Gemini request timed out after {timeout}s", retryable=True) from exc
            except requests.exceptions.ConnectionError as exc:
                raise ProviderError(f"Gemini connection failed: {exc}", retryable=True) from exc
            latency = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                raw = resp.json()
                self.validate_response(raw)
                return self._parse_response(raw, current_model, latency)

            if resp.status_code == 404:
                logger.warning(f"Gemini model {current_model} returned 404, trying next candidate model...")
                last_error = ProviderError(f"Gemini API error 404: {resp.text[:300]}", status_code=404, retryable=False)
                continue

            retryable = resp.status_code not in _NON_RETRYABLE_STATUS
            raise ProviderError(
                f"Gemini API error {resp.status_code}: {resp.text[:500]}",
                status_code=resp.status_code,
                retryable=retryable,
            )

        raise last_error or ProviderError("All candidate Gemini models returned 404", status_code=404, retryable=False)

    def validate_response(self, raw: Dict[str, Any]) -> None:
        if "candidates" not in raw or not raw["candidates"]:
            raise ProviderError("Gemini response missing 'candidates'", retryable=False)
        first = raw["candidates"][0]
        if "content" not in first or "parts" not in first["content"] or not first["content"]["parts"]:
            raise ProviderError("Gemini candidate missing text parts", retryable=False)

    def _parse_response(self, raw: Dict[str, Any], model: str, latency: float) -> LLMResponse:
        candidate = raw["candidates"][0]
        parts = candidate["content"]["parts"]
        content = "".join([part.get("text", "") for part in parts])
        
        usage_meta = raw.get("usageMetadata", {})
        usage = LLMUsage(
            prompt_tokens=usage_meta.get("promptTokenCount", 0),
            completion_tokens=usage_meta.get("candidatesTokenCount", 0),
            total_tokens=usage_meta.get("totalTokenCount", 0),
        )
        return LLMResponse(
            content=content,
            model=model,
            usage=usage,
            raw_response=raw,
            provider=self.name,
            latency_ms=latency,
        )
