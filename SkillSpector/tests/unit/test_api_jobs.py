# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for scan job creation and worker processing."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from skillspector import __version__
from skillspector.api.config import ApiConfig
from skillspector.api.main import create_app
from skillspector.api.store import ApiStore
from skillspector.api.worker import process_next_scan_once


def build_test_client(tmp_path: Path) -> tuple[TestClient, ApiStore]:
    """Create an API app and store bound to a temporary SQLite database."""
    config = ApiConfig(
        host="127.0.0.1",
        port=8001,
        data_dir=str(tmp_path / "data"),
        work_dir=str(tmp_path / "work"),
        db_path=str(tmp_path / "data" / "skillspector.db"),
        worker_poll_seconds=0.01,
        embedded_worker_enabled=False,
    )
    config.ensure_directories()
    app = create_app(config)
    return TestClient(app), app.state.store


def test_create_scan_and_get_status(tmp_path: Path) -> None:
    """POST /v1/scans queues a deterministic scan that can be polled."""
    client, _store = build_test_client(tmp_path)

    response = client.post(
        "/v1/scans",
        json={
            "target": "https://github.com/example/repo",
            "mode": "deterministic",
            "formats": ["json", "markdown"],
        },
    )

    assert response.status_code == 202
    created = response.json()
    assert created["status"] == "queued"
    assert created["mode"] == "deterministic"

    status_response = client.get(f"/v1/scans/{created['scan_id']}")
    assert status_response.status_code == 200
    status_data = status_response.json()
    assert status_data["target"] == "https://github.com/example/repo"
    assert status_data["requested_formats"] == ["json", "markdown"]
    assert status_data["status"] == "queued"


def test_create_scan_with_agent_review_fields(tmp_path: Path) -> None:
    """POST /v1/scans persists bounded agent-review request settings."""
    client, store = build_test_client(tmp_path)

    response = client.post(
        "/v1/scans",
        json={
            "target": "https://github.com/example/repo",
            "mode": "deterministic",
            "formats": ["json"],
            "agent_review_enabled": True,
            "agent_review_skill": "deterministic_triage",
            "agent_review_prompt": "Focus on duplicate findings.",
            "agent_review_model": "gpt-4.1-mini",
        },
    )

    assert response.status_code == 202
    created = response.json()
    assert created["agent_review_enabled"] is True

    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["agent_review_requested"] is True
    assert scan["agent_review_skill"] == "deterministic_triage"
    assert scan["agent_review_prompt"] == "Focus on duplicate findings."
    assert scan["agent_review_model"] == "gpt-4.1-mini"


def test_get_scan_missing_returns_404(tmp_path: Path) -> None:
    """Polling a missing scan id returns 404."""
    client, _store = build_test_client(tmp_path)

    response = client.get("/v1/scans/missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "scan not found"


def test_worker_processes_queued_scan(monkeypatch, tmp_path: Path) -> None:
    """Worker claims a queued scan, stores summary, and marks it completed."""
    _client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json", "terminal"],
    )

    async def fake_run_deterministic_scan(target: str, requested_formats: list[str]):
        assert target == "https://github.com/example/repo"
        assert requested_formats == ["json", "terminal"]
        summary = {
            "risk_score": 12,
            "severity": "LOW",
            "recommendation": "SAFE",
            "safe_to_install": True,
            "findings_count": 1,
            "findings_by_severity": {"LOW": 1},
            "findings_by_category": {"Supply Chain": 1},
            "scanner_version": __version__,
            "scan_mode": "static-only",
            "llm_requested": False,
            "llm_used": False,
        }
        reports = {
            "json": {"content": "{}", "content_type": "application/json"},
            "terminal": {"content": "ok", "content_type": "text/plain; charset=utf-8"},
        }
        findings = [
            {
                "id": "SC1",
                "category": "Supply Chain",
                "pattern": "Unpinned Dependencies",
                "severity": "LOW",
                "confidence": 0.6,
                "location": {"file": "requirements.txt", "start_line": 1, "end_line": None},
                "finding": "package",
                "explanation": "test",
                "remediation": "pin it",
                "code_snippet": "package",
                "tags": [],
            }
        ]
        return summary, reports, findings

    monkeypatch.setattr(
        "skillspector.api.worker.run_deterministic_scan",
        fake_run_deterministic_scan,
    )

    processed = __import__("asyncio").run(process_next_scan_once(store))

    assert processed is True
    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["status"] == "completed"
    assert scan["risk_score"] == 12
    assert scan["severity"] == "LOW"
    assert scan["recommendation"] == "SAFE"
    assert scan["findings_count"] == 1
    assert sorted(scan["available_reports"]) == ["json", "terminal"]


def test_worker_marks_failed_scan(monkeypatch, tmp_path: Path) -> None:
    """Worker records a failed scan when the deterministic scan raises."""
    _client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
    )

    async def fake_run_deterministic_scan(_target: str, _requested_formats: list[str]):
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(
        "skillspector.api.worker.run_deterministic_scan",
        fake_run_deterministic_scan,
    )

    processed = __import__("asyncio").run(process_next_scan_once(store))

    assert processed is True
    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["status"] == "failed"
    assert "scan exploded" in (scan["error"] or "")


def test_fail_running_scans_marks_interrupted_jobs(tmp_path: Path) -> None:
    """Interrupted running scans should be recoverable on service startup."""
    _client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
    )
    claimed = store.claim_next_scan()
    assert claimed is not None
    assert claimed["scan_id"] == created["scan_id"]
    assert claimed["status"] == "running"

    recovered = store.fail_running_scans("scan interrupted by service restart before completion")

    assert recovered == 1
    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["status"] == "failed"
    assert "service restart" in (scan["error"] or "")


def test_embedded_worker_processes_scan_during_app_lifespan(monkeypatch, tmp_path: Path) -> None:
    """The API should consume queued scans by default when the app is running."""
    config = ApiConfig(
        host="127.0.0.1",
        port=8001,
        data_dir=str(tmp_path / "data"),
        work_dir=str(tmp_path / "work"),
        db_path=str(tmp_path / "data" / "skillspector.db"),
        worker_poll_seconds=0.01,
        embedded_worker_enabled=True,
    )
    config.ensure_directories()

    async def fake_run_deterministic_scan(_target: str, requested_formats: list[str]):
        reports = {
            fmt: {"content": "{}", "content_type": "application/json"}
            if fmt in {"json", "sarif"}
            else {"content": "ok", "content_type": "text/plain; charset=utf-8"}
            for fmt in requested_formats
        }
        findings = [
            {
                "id": "AST1",
                "category": "Code Execution",
                "pattern": "os.system",
                "severity": "HIGH",
                "confidence": 0.9,
                "location": {"file": "skill.py", "start_line": 12, "end_line": None},
                "finding": "os.system(user_input)",
                "explanation": "Command execution sink",
                "remediation": "Use a fixed argv list.",
                "code_snippet": "os.system(user_input)",
                "tags": [],
            }
        ]
        summary = {
            "risk_score": 84,
            "severity": "HIGH",
            "recommendation": "UNSAFE",
            "safe_to_install": False,
            "findings_count": 1,
            "findings_by_severity": {"HIGH": 1},
            "findings_by_category": {"Code Execution": 1},
            "scanner_version": __version__,
            "scan_mode": "static-only",
            "llm_requested": False,
            "llm_used": False,
        }
        return summary, reports, findings

    monkeypatch.setattr(
        "skillspector.api.worker.run_deterministic_scan",
        fake_run_deterministic_scan,
    )

    with TestClient(create_app(config)) as client:
        created = client.post(
            "/v1/scans",
            json={
                "target": "https://github.com/example/repo",
                "mode": "deterministic",
                "formats": ["json", "markdown"],
            },
        ).json()

        deadline = time.time() + 1.0
        status_data = None
        while time.time() < deadline:
            status_response = client.get(f"/v1/scans/{created['scan_id']}")
            assert status_response.status_code == 200
            status_data = status_response.json()
            if status_data["status"] == "completed":
                break
            time.sleep(0.02)

        assert status_data is not None
        assert status_data["status"] == "completed"
        assert status_data["findings_count"] == 1


def test_worker_passes_agent_review_kwargs_when_requested(monkeypatch, tmp_path: Path) -> None:
    """Worker should forward bounded agent-review settings only when requested."""
    _client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
        agent_review_enabled=True,
        agent_review_skill="deterministic_triage",
        agent_review_prompt="Focus on top risks only.",
        agent_review_model="gpt-4.1-mini",
    )
    captured: dict[str, object] = {}

    async def fake_run_deterministic_scan(
        target: str,
        requested_formats: list[str],
        **kwargs: object,
    ):
        captured["target"] = target
        captured["requested_formats"] = requested_formats
        captured["kwargs"] = kwargs
        return (
            {
                "risk_score": 77,
                "severity": "HIGH",
                "recommendation": "UNSAFE",
                "safe_to_install": False,
                "findings_count": 1,
                "findings_by_severity": {"HIGH": 1},
                "findings_by_category": {"Code Execution": 1},
                "scanner_version": __version__,
                "scan_mode": "static-only",
                "llm_requested": False,
                "llm_used": False,
                "agent_review_requested": True,
                "agent_review_used": True,
                "agent_review_status": "completed",
                "agent_review_verdict": "mixed_signal",
                "agent_review_summary": "One strong finding, one questionable duplicate.",
                "agent_review_report": {
                    "overall_verdict": "mixed_signal",
                    "executive_summary": "One strong finding, one questionable duplicate.",
                },
            },
            {"json": {"content": "{}", "content_type": "application/json"}},
            [
                {
                    "id": "AST1",
                    "category": "Code Execution",
                    "pattern": "os.system",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "location": {"file": "skill.py", "start_line": 12, "end_line": None},
                    "finding": "os.system(user_input)",
                    "explanation": "Command execution sink",
                    "remediation": "Use a fixed argv list.",
                    "code_snippet": "os.system(user_input)",
                    "tags": [],
                }
            ],
        )

    monkeypatch.setattr(
        "skillspector.api.worker.run_deterministic_scan",
        fake_run_deterministic_scan,
    )

    processed = __import__("asyncio").run(process_next_scan_once(store))

    assert processed is True
    assert captured["target"] == "https://github.com/example/repo"
    assert captured["requested_formats"] == ["json"]
    assert captured["kwargs"] == {
        "agent_review_enabled": True,
        "agent_review_skill": "deterministic_triage",
        "agent_review_prompt": "Focus on top risks only.",
        "agent_review_model": "gpt-4.1-mini",
    }

    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["agent_review_requested"] is True
    assert scan["agent_review_used"] is True
    assert scan["agent_review_status"] == "completed"
    assert scan["agent_review_verdict"] == "mixed_signal"


def test_agent_review_endpoint_returns_stored_report(tmp_path: Path) -> None:
    """Completed scans should expose the stored bounded agent review payload."""
    client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
        agent_review_enabled=True,
        agent_review_skill="deterministic_triage",
    )
    store.complete_scan(
        created["scan_id"],
        summary={
            "risk_score": 91,
            "severity": "CRITICAL",
            "recommendation": "UNSAFE",
            "safe_to_install": False,
            "findings_count": 2,
            "findings_by_severity": {"CRITICAL": 1, "HIGH": 1},
            "findings_by_category": {"Code Execution": 2},
            "scanner_version": __version__,
            "scan_mode": "static-only",
            "llm_requested": False,
            "llm_used": False,
            "agent_review_requested": True,
            "agent_review_used": True,
            "agent_review_status": "completed",
            "agent_review_verdict": "confirm_unsafe",
            "agent_review_summary": "Deterministic findings were confirmed by bounded review.",
            "agent_review_report": {
                "overall_verdict": "confirm_unsafe",
                "executive_summary": "Deterministic findings were confirmed by bounded review.",
                "top_confirmed_risks": ["AST1|skill.py|12"],
                "likely_false_positives": [],
                "likely_duplicates": [],
                "follow_up_actions": ["Block install until remediated."],
                "review_confidence": 0.87,
            },
        },
        reports={"json": {"content": "{}", "content_type": "application/json"}},
        findings=[
            {
                "id": "AST1",
                "category": "Code Execution",
                "pattern": "os.system",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "location": {"file": "skill.py", "start_line": 12, "end_line": None},
                "finding": "os.system(user_input)",
                "explanation": "Command execution sink",
                "remediation": "Use a fixed argv list.",
                "code_snippet": "os.system(user_input)",
                "tags": [],
            }
        ],
    )

    response = client.get(f"/v1/scans/{created['scan_id']}/agent-review")

    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == created["scan_id"]
    assert data["requested"] is True
    assert data["used"] is True
    assert data["status"] == "completed"
    assert data["verdict"] == "confirm_unsafe"
    assert data["summary"] == "Deterministic findings were confirmed by bounded review."
    assert data["report"]["overall_verdict"] == "confirm_unsafe"
