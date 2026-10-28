"""The scanner's "What this skill can do" list: stored on the scan row and
returned by the scan detail API, with NULL for scans recorded before it."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import JSON

from backend.domain.models.entities import ScanModel
from backend.domain.models.scanner_protocol import ScannerResult
from backend.repositories.scan_repository import ScanRepository
from backend.services.scan_service import ScanService
from backend.services.scanner_client import ScannerClient
from tests.test_scanner_client import make_executable, success_payload

CAPABILITY = {
    "rule_id": "AST4",
    "label": "Runs shell commands",
    "location": {"file": "skills/report/run.py", "start_line": 3, "end_line": None},
    "snippet": "subprocess.run(['git', 'status'])",
}


def test_capabilities_column_is_nullable_json() -> None:
    column = ScanModel.__table__.c.capabilities
    assert isinstance(column.type, JSON)
    assert column.nullable is True
    assert column.default is None


class RecordingConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    async def run_sync(self, fn: Any) -> None:
        return None

    async def execute(self, statement: Any, params: Any = None) -> Any:
        self.statements.append(str(statement))

        class Rows:
            def mappings(self) -> list[dict[str, Any]]:
                return []

        return Rows()


class RecordingEngine:
    def __init__(self) -> None:
        self.connection = RecordingConnection()

    @asynccontextmanager
    async def begin(self):
        yield self.connection

    async def dispose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_startup_adds_the_capabilities_column(monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.api.main as main

    engine = RecordingEngine()
    monkeypatch.setattr(main, "engine", engine)
    async with main.lifespan(main.app):
        pass
    assert "ALTER TABLE scans ADD COLUMN IF NOT EXISTS capabilities JSON" in engine.connection.statements


@pytest.mark.asyncio
async def test_scanner_client_requests_and_parses_capabilities(tmp_path: Path) -> None:
    payload = success_payload()
    payload["result"]["capabilities"] = [CAPABILITY]  # type: ignore[index]
    received = tmp_path / "request.json"
    executable = make_executable(
        tmp_path,
        f"import sys\nopen({str(received)!r}, 'w').write(sys.stdin.read())\nprint({json.dumps(payload)!r})\n",
    )

    result = await ScannerClient(executable=executable, timeout_seconds=5).scan(
        target="fixture", asset_type="agent_skill", output_formats=["json"]
    )

    assert json.loads(received.read_text())["include_capabilities"] is True
    assert result.capabilities is not None
    assert result.capabilities[0].label == "Runs shell commands"
    assert result.capabilities[0].location.start_line == 3


def test_scanner_result_without_capabilities_is_valid() -> None:
    result = ScannerResult.model_validate(success_payload()["result"])
    assert result.capabilities is None


class FakeSession:
    def __init__(self) -> None:
        self.statements: list[Any] = []
        self.added: list[Any] = []

    async def execute(self, statement: Any) -> None:
        self.statements.append(statement)

    def add(self, value: Any) -> None:
        self.added.append(value)

    async def commit(self) -> None:
        return None


@pytest.mark.asyncio
async def test_repository_stores_capabilities_on_the_scan_row() -> None:
    session = FakeSession()
    await ScanRepository(session).save_scan_success(  # type: ignore[arg-type]
        scan_id="scan-1",
        summary_dict=success_payload()["result"]["summary"],  # type: ignore[index]
        findings_list=[],
        reports_dict={},
        capabilities_list=[CAPABILITY],
    )
    params = session.statements[0].compile().params
    assert params["capabilities"] == [CAPABILITY]


@pytest.mark.asyncio
@pytest.mark.parametrize("returned, stored", [([CAPABILITY], [CAPABILITY]), (None, [])])
async def test_worker_stores_the_returned_capabilities(
    monkeypatch: pytest.MonkeyPatch, returned: list[dict[str, Any]] | None, stored: list[dict[str, Any]]
) -> None:
    import backend.workers.scan_worker as worker

    result_payload = dict(success_payload()["result"])  # type: ignore[arg-type]
    if returned is not None:
        result_payload["capabilities"] = returned
    saved: dict[str, Any] = {}

    class FakeScannerClient:
        async def scan(self, **_: Any) -> ScannerResult:
            return ScannerResult.model_validate(result_payload)

    class FakeRepository:
        def __init__(self, session: Any) -> None:
            return None

        async def update_stage(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def save_scan_success(self, **kwargs: Any) -> None:
            saved.update(kwargs)

        async def save_scan_failure(self, scan_id: str, error_message: str) -> None:
            raise AssertionError(error_message)

    @asynccontextmanager
    async def fake_session():
        yield object()

    monkeypatch.setattr(worker, "ScannerClient", FakeScannerClient)
    monkeypatch.setattr(worker, "ScanRepository", FakeRepository)
    monkeypatch.setattr(worker, "WorkerAsyncSessionLocal", fake_session)

    await worker._execute_scan_pipeline(
        scan_id="scan-1", target="fixture", asset_type="agent_skill", scan_scope="skill_folders", include_readme=False
    )

    assert saved["capabilities_list"] == stored


def completed_scan(capabilities: list[dict[str, Any]] | None) -> ScanModel:
    now = datetime(2026, 10, 28, tzinfo=timezone.utc)
    return ScanModel(
        id="scan-1",
        asset_target="https://github.com/example/skills",
        repository_key="github.com/example/skills",
        asset_type="agent_skill",
        scan_scope="skill_folders",
        include_readme=False,
        status="COMPLETED",
        current_stage="COMPLETED",
        risk_score=12,
        severity="LOW",
        recommendation="SAFE",
        safe_to_install=True,
        findings_count=0,
        findings_by_severity={},
        findings_by_category={},
        reports_blob={},
        capabilities=capabilities,
        created_at=now,
        started_at=now,
        completed_at=now,
    )


class FakeScanRepository:
    def __init__(self, scan: ScanModel) -> None:
        self.scan = scan

    async def get_scan_by_id(self, scan_id: str) -> ScanModel:
        return self.scan

    async def get_findings_for_scan(self, scan_id: str) -> list[Any]:
        return []


@pytest.mark.asyncio
async def test_scan_detail_returns_capabilities() -> None:
    detail = await ScanService(FakeScanRepository(completed_scan([CAPABILITY]))).get_scan_details("scan-1")  # type: ignore[arg-type]
    assert detail is not None and detail.capabilities is not None
    body = detail.model_dump(mode="json")
    assert body["capabilities"] == [
        {
            "rule_id": "AST4",
            "label": "Runs shell commands",
            "location": {"file": "skills/report/run.py", "start_line": 3, "end_line": None},
            "snippet": "subprocess.run(['git', 'status'])",
            "documentation_url": "/v1/rules/AST4",
        }
    ]


@pytest.mark.asyncio
async def test_scan_detail_returns_null_for_an_old_scan() -> None:
    detail = await ScanService(FakeScanRepository(completed_scan(None))).get_scan_details("scan-1")  # type: ignore[arg-type]
    assert detail is not None
    assert detail.model_dump(mode="json")["capabilities"] is None


@pytest.mark.asyncio
async def test_scan_detail_skips_malformed_stored_entries() -> None:
    detail = await ScanService(  # type: ignore[arg-type]
        FakeScanRepository(completed_scan([CAPABILITY, {"label": "missing rule and location"}]))
    ).get_scan_details("scan-1")
    assert detail is not None and detail.capabilities is not None
    assert [entry.rule_id for entry in detail.capabilities] == ["AST4"]
