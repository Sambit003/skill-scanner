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

"""Tests for scan findings and stored report retrieval endpoints."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from skillspector import __version__
from skillspector.api.store import ApiStore

from .test_api_jobs import build_test_client


def complete_test_scan(store: ApiStore, scan_id: str) -> None:
    """Persist a completed scan with reports and one normalized finding."""
    store.complete_scan(
        scan_id,
        summary={
            "risk_score": 42,
            "severity": "MEDIUM",
            "recommendation": "CAUTION",
            "safe_to_install": False,
            "findings_count": 1,
            "findings_by_severity": {"MEDIUM": 1},
            "findings_by_category": {"Dangerous Code Execution": 1},
            "scanner_version": __version__,
            "scan_mode": "static-only",
            "llm_requested": False,
            "llm_used": False,
        },
        reports={
            "json": {
                "content": json.dumps({"ok": True, "findings": [{"id": "AST1"}]}),
                "content_type": "application/json",
            },
            "markdown": {
                "content": "# Skill Report\n\n- Finding: AST1\n",
                "content_type": "text/markdown; charset=utf-8",
            },
            "sarif": {
                "content": json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "SkillSpector"}},
                                "results": [],
                            }
                        ],
                    }
                ),
                "content_type": "application/sarif+json",
            },
            "terminal": {
                "content": "SkillSpector report\nAST1 detected\n",
                "content_type": "text/plain; charset=utf-8",
            },
        },
        findings=[
            {
                "id": "AST1",
                "category": "Dangerous Code Execution",
                "pattern": "exec() call detected",
                "severity": "HIGH",
                "confidence": 0.85,
                "location": {
                    "file": "scripts/helper.py",
                    "start_line": 12,
                    "end_line": None,
                },
                "finding": "exec(user_input)",
                "explanation": "Direct exec() call allows arbitrary code execution.",
                "remediation": "Replace exec() with a safe alternative.",
                "code_snippet": "exec(user_input)",
                "tags": [],
            }
        ],
    )


def create_completed_scan(tmp_path: Path) -> tuple[TestClient, str]:
    """Create a completed scan job in the temp store and return the client + id."""
    client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json", "markdown", "sarif", "terminal"],
    )
    complete_test_scan(store, created["scan_id"])
    return client, created["scan_id"]


def test_findings_endpoint_returns_normalized_findings(tmp_path: Path) -> None:
    """Completed scans expose normalized findings."""
    client, scan_id = create_completed_scan(tmp_path)

    response = client.get(f"/v1/scans/{scan_id}/findings")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["status"] == "completed"
    assert body["total"] == 1
    finding = body["findings"][0]
    assert finding["id"] == "AST1"
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] == 0.85
    assert finding["location"]["file"] == "scripts/helper.py"
    assert finding["location"]["start_line"] == 12


def test_report_endpoints_return_expected_content_types(tmp_path: Path) -> None:
    """Completed scans expose every stored report format with correct content types."""
    client, scan_id = create_completed_scan(tmp_path)

    json_response = client.get(f"/v1/scans/{scan_id}/reports/json")
    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith("application/json")
    assert json_response.json()["ok"] is True

    markdown_response = client.get(f"/v1/scans/{scan_id}/reports/markdown")
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# Skill Report" in markdown_response.text

    sarif_response = client.get(f"/v1/scans/{scan_id}/reports/sarif")
    assert sarif_response.status_code == 200
    assert sarif_response.headers["content-type"].startswith("application/sarif+json")
    assert sarif_response.json()["version"] == "2.1.0"

    terminal_response = client.get(f"/v1/scans/{scan_id}/reports/terminal")
    assert terminal_response.status_code == 200
    assert terminal_response.headers["content-type"].startswith("text/plain")
    assert "AST1 detected" in terminal_response.text


def test_findings_endpoint_rejects_incomplete_scan(tmp_path: Path) -> None:
    """Findings are not available until a scan completes."""
    client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
    )

    response = client.get(f"/v1/scans/{created['scan_id']}/findings")

    assert response.status_code == 409
    assert "scan not completed" in response.json()["detail"]
