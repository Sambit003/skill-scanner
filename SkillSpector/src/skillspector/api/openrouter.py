"""OpenRouter catalog helpers for the frontend BYOK flow."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
OPENROUTER_MODELS_TTL_SECONDS = 900

_cache_lock = threading.Lock()
_cache_value: dict[str, Any] | None = None
_cache_expires_at = 0.0


def _normalize_model(item: dict[str, Any]) -> dict[str, Any]:
    pricing = item.get("pricing") or {}
    architecture = item.get("architecture") or {}
    top_provider = item.get("top_provider") or {}
    return {
        "id": str(item.get("id") or ""),
        "name": str(item.get("name") or item.get("id") or ""),
        "description": item.get("description"),
        "context_length": item.get("context_length"),
        "max_completion_tokens": top_provider.get("max_completion_tokens"),
        "modality": architecture.get("modality"),
        "prompt_price": pricing.get("prompt"),
        "completion_price": pricing.get("completion"),
        "supported_parameters": list(item.get("supported_parameters") or []),
    }


def list_openrouter_models(*, force_refresh: bool = False) -> dict[str, Any]:
    """Return a cached normalized OpenRouter models payload."""
    global _cache_value, _cache_expires_at

    now = time.time()
    with _cache_lock:
        if not force_refresh and _cache_value is not None and now < _cache_expires_at:
            return _cache_value

    with httpx.Client(timeout=20.0, follow_redirects=True) as client:
        response = client.get(OPENROUTER_MODELS_URL)
        response.raise_for_status()
        payload = response.json()

    normalized = {
        "source": "openrouter",
        "fetched_at": int(now),
        "total_count": int(payload.get("total_count") or 0),
        "items": [_normalize_model(item) for item in list(payload.get("data") or [])],
    }

    with _cache_lock:
        _cache_value = normalized
        _cache_expires_at = time.time() + OPENROUTER_MODELS_TTL_SECONDS

    return normalized
