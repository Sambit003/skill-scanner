"""Validation and runtime guardrails for the API."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from skillspector.input_handler import (
    ALLOWED_DOWNLOAD_HOSTS,
    ALLOWED_GIT_HOSTS,
    InputHandler,
)


def validate_scan_target(target: str, *, max_target_length: int) -> None:
    """Validate target syntax and SSRF policy before queueing a scan."""
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target must not be empty")
    if len(target) > max_target_length:
        raise HTTPException(
            status_code=400,
            detail=f"target exceeds max length of {max_target_length} characters",
        )

    handler = InputHandler()
    candidate = Path(target)

    try:
        if handler._is_git_url(target):
            handler._validate_url_host(target, ALLOWED_GIT_HOSTS)
            return
        if handler._is_file_url(target):
            handler._validate_url_host(target, ALLOWED_DOWNLOAD_HOSTS)
            return
        if candidate.exists():
            if candidate.is_dir() or candidate.is_file():
                return
        if target.endswith(".zip") or target.endswith(".md"):
            raise HTTPException(status_code=400, detail=f"local path does not exist: {target}")
        raise HTTPException(
            status_code=400,
            detail="unsupported target; use a Git URL, file URL, local file, zip, or directory",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def normalize_formats(formats: list[str]) -> list[str]:
    """Deduplicate requested report formats while preserving order."""
    deduped = list(dict.fromkeys(formats))
    if len(deduped) > 4:
        raise HTTPException(status_code=400, detail="at most 4 report formats are allowed")
    return deduped


def cleanup_stale_workdirs(work_dir: str, *, max_age_seconds: int) -> int:
    """Remove stale API temp directories under the configured work directory."""
    root = Path(work_dir)
    if not root.exists():
        return 0

    now = datetime.now(UTC).timestamp()
    removed = 0
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if not child.name.startswith("skillspector_"):
            continue
        try:
            age_seconds = now - child.stat().st_mtime
        except OSError:
            continue
        if age_seconds < max_age_seconds:
            continue
        shutil.rmtree(child, ignore_errors=True)
        removed += 1
    return removed


def polling_metadata(status: str, default_poll_after_ms: int) -> dict[str, Any]:
    """Return polling-friendly metadata for the frontend."""
    is_terminal = status in {"completed", "failed", "canceled"}
    return {
        "is_terminal": is_terminal,
        "next_poll_after_ms": 0 if is_terminal else default_poll_after_ms,
    }
