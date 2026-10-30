"""The scanner's verdict_reason: stored on the scan row and returned by the
scan detail API, with NULL for scans recorded before it. While risk scores are
hidden, the risk number is left out of the reason and of stored reports."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import Text

from backend.core.config import settings
from backend.domain.models.entities import ScanModel
from backend.repositories.scan_repository import ScanRepository
from backend.services.scan_service import ScanService
from backend.services.score_visibility import redact_report_content, visible_verdict_reason
from tests.test_capabilities import FakeScanRepository, FakeSession, RecordingEngine, completed_scan
from tests.test_scanner_client import success_payload

FLOOR_REASON = "CAUTION: hidden instructions (P2, SKILL.md:23)"
SCORE_REASON = "CAUTION: risk 34 from 2 evidence findings"


def test_verdict_reason_column_is_nullable_text() -> None:
    column = ScanModel.__table__.c.verdict_reason
    assert isinstance(column.type, Text)
    assert column.nullable is True
    assert column.default is None


@pytest.mark.asyncio
async def test_startup_adds_the_verdict_reason_column(monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.api.main as main

    engine = RecordingEngine()
    monkeypatch.setattr(main, "engine", engine)
    async with main.lifespan(main.app):
        pass
    assert "ALTER TABLE scans ADD COLUMN IF NOT EXISTS verdict_reason TEXT" in engine.connection.statements


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [FLOOR_REASON, None])
async def test_repository_stores_the_verdict_reason(reason: str | None) -> None:
    summary = dict(success_payload()["result"]["summary"])  # type: ignore[index]
    if reason is not None:
        summary["verdict_reason"] = reason
    session = FakeSession()
    await ScanRepository(session).save_scan_success(  # type: ignore[arg-type]
        scan_id="scan-1", summary_dict=summary, findings_list=[], reports_dict={}
    )
    assert session.statements[0].compile().params["verdict_reason"] == reason


def scan_with_reason(reason: str | None) -> ScanModel:
    scan = completed_scan(None)
    scan.verdict_reason = reason
    return scan


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored, returned",
    [
        (FLOOR_REASON, FLOOR_REASON),
        (SCORE_REASON, "CAUTION: 2 evidence findings"),
        ("SAFE: risk 4 from exposure only, no evidence findings", "SAFE: exposure only, no evidence findings"),
        (None, None),
    ],
)
async def test_scan_detail_returns_the_reason_without_the_hidden_score(stored: str | None, returned: str | None) -> None:
    detail = await ScanService(FakeScanRepository(scan_with_reason(stored))).get_scan_details("scan-1")  # type: ignore[arg-type]
    assert detail is not None
    assert detail.model_dump(mode="json")["verdict_reason"] == returned


@pytest.mark.asyncio
async def test_scan_detail_keeps_the_score_when_scores_are_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SHOW_RISK_SCORES", True)
    detail = await ScanService(FakeScanRepository(scan_with_reason(SCORE_REASON))).get_scan_details("scan-1")  # type: ignore[arg-type]
    assert detail is not None and detail.verdict_reason == SCORE_REASON


def test_reason_without_a_score_is_unchanged() -> None:
    assert visible_verdict_reason(FLOOR_REASON) == FLOOR_REASON
    assert visible_verdict_reason("SAFE: no evidence findings") == "SAFE: no evidence findings"


def test_json_report_redacts_the_score_in_the_reason() -> None:
    report = json.dumps({"summary": {"risk_score": 34, "verdict_reason": SCORE_REASON}, "findings": []})

    summary: dict[str, Any] = json.loads(redact_report_content(report, "json"))["summary"]

    assert summary["risk_score"] is None
    assert summary["verdict_reason"] == "CAUTION: 2 evidence findings"


def test_markdown_report_redacts_the_score_in_the_reason() -> None:
    report = "**Risk:** 34/100 (MEDIUM)  \n**Verdict reason:** CAUTION: risk 34 from 2 evidence findings\n"

    redacted = redact_report_content(report, "markdown")

    assert "34" not in redacted
    assert "**Verdict reason:** CAUTION: 2 evidence findings\n" in redacted


def test_terminal_report_redacts_the_score_in_the_reason() -> None:
    report = "ScanKernel: risk 34/100 MEDIUM — CAUTION\nVerdict reason: CAUTION: risk 34 from 2 evidence findings\n"

    redacted = redact_report_content(report, "terminal")

    assert "34" not in redacted
    assert "Verdict reason: CAUTION: 2 evidence findings\n" in redacted
