"""Ephemeral in-memory BYOK secret storage for queued scans."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class AgentReviewSecret:
    """Non-persistent LLM secret material for one scan."""

    provider: str
    api_key: str


class AgentReviewSecretVault:
    """Thread-safe in-memory secret vault keyed by scan id."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._secrets: dict[str, AgentReviewSecret] = {}

    def put(self, scan_id: str, secret: AgentReviewSecret) -> None:
        with self._lock:
            self._secrets[scan_id] = secret

    def pop(self, scan_id: str) -> AgentReviewSecret | None:
        with self._lock:
            return self._secrets.pop(scan_id, None)

    def delete(self, scan_id: str) -> None:
        with self._lock:
            self._secrets.pop(scan_id, None)


agent_review_secret_vault = AgentReviewSecretVault()

