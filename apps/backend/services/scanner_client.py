"""Async subprocess client for the ScanKernel engine protocol."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from pydantic import ValidationError

from backend.core.config import settings
from backend.domain.models.scanner_protocol import (
    ScannerProtocolResult,
    ScannerResult,
    ScannerRuleDoc,
    ScannerRuleResult,
    ScannerRulesResult,
    ScannerSuccessEnvelope,
)


class ScannerClientError(RuntimeError):
    """Raised when the scanner process cannot produce a valid successful response."""


class ScannerClient:
    def __init__(self, executable: str | None = None, timeout_seconds: float | None = None):
        self.executable = executable or settings.SCAN_KERNEL_EXECUTABLE
        self.timeout_seconds = timeout_seconds or settings.SCAN_KERNEL_TIMEOUT_SECONDS

    async def scan(
        self,
        *,
        target: str,
        asset_type: str,
        output_formats: list[str],
    ) -> ScannerResult:
        request: dict[str, Any] = {
            "operation": "scan",
            "protocol_version": "1",
            "target": target,
            "asset_type": asset_type,
            "output_formats": output_formats,
            "timeout_seconds": self.timeout_seconds,
        }

        result = await self._execute(request)
        if not isinstance(result, ScannerResult):
            raise ScannerClientError("Scanner response violated protocol v1: expected scan result")
        return result

    async def list_rules(self) -> list[ScannerRuleDoc]:
        result = await self._execute({"operation": "list_rules", "protocol_version": "1"})
        if not isinstance(result, ScannerRulesResult):
            raise ScannerClientError("Scanner response violated protocol v1: expected rules result")
        return result.items

    async def get_rule(self, rule_id: str) -> ScannerRuleDoc:
        result = await self._execute(
            {"operation": "get_rule", "protocol_version": "1", "rule_id": rule_id}
        )
        if not isinstance(result, ScannerRuleResult):
            raise ScannerClientError("Scanner response violated protocol v1: expected rule result")
        return result.rule

    async def _execute(self, request: dict[str, Any]) -> ScannerProtocolResult:
        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise ScannerClientError(
                f"Unable to start scanner executable {self.executable!r}: {exc}"
            ) from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(json.dumps(request).encode("utf-8")),
                timeout=self.timeout_seconds,
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ScannerClientError(
                f"Scanner exceeded the {self.timeout_seconds:g}s execution timeout"
            ) from exc

        stderr_text = stderr.decode("utf-8", errors="replace").strip()[-2000:]
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            detail = f": {stderr_text}" if stderr_text else ""
            raise ScannerClientError(f"Scanner returned malformed JSON{detail}") from exc

        if not isinstance(payload, dict):
            raise ScannerClientError("Scanner response violated protocol v1: expected a JSON object")

        if process.returncode != 0 or payload.get("ok") is not True:
            error = payload.get("error")
            message = error.get("message") if isinstance(error, dict) else None
            detail = message or stderr_text or f"exit code {process.returncode}"
            raise ScannerClientError(f"Scanner failed: {detail}")

        try:
            return ScannerSuccessEnvelope.model_validate(payload).result
        except ValidationError as exc:
            raise ScannerClientError(f"Scanner response violated protocol v1: {exc}") from exc
