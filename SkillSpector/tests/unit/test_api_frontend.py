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

"""Tests for frontend-oriented API endpoints and enrichments."""

from __future__ import annotations

from pathlib import Path

from .test_api_jobs import build_test_client
from .test_api_reports import create_completed_scan


def test_list_scans_returns_frontend_summary_fields(tmp_path: Path) -> None:
    """Scan list endpoint should expose frontend-ready summary cards."""
    client, scan_id = create_completed_scan(tmp_path)

    response = client.get("/v1/scans")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["scan_id"] == scan_id
    assert item["headline"] == "Needs Review"
    assert item["primary_verdict"] == "caution"
    assert item["report_downloads"]
    assert item["severity_breakdown"][0]["label"] == "MEDIUM"


def test_findings_endpoint_supports_filters_and_frontend_fields(tmp_path: Path) -> None:
    """Findings endpoint should support frontend filters and enriched fields."""
    client, scan_id = create_completed_scan(tmp_path)

    response = client.get(
        f"/v1/scans/{scan_id}/findings",
        params={"severity": "HIGH", "rule_family": "AST", "q": "exec", "page_size": 10},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    finding = body["findings"][0]
    assert finding["rule_family"] == "AST"
    assert finding["documentation_url"] == "/v1/rules/AST1"
    assert finding["file_path_display"] == "scripts/helper.py:12"


def test_reports_manifest_and_events_endpoints(tmp_path: Path) -> None:
    """Frontend report manifest and event timeline endpoints should return data."""
    client, scan_id = create_completed_scan(tmp_path)

    manifest_response = client.get(f"/v1/scans/{scan_id}/reports")
    assert manifest_response.status_code == 200
    manifest = manifest_response.json()
    assert manifest["scan_id"] == scan_id
    assert {item["format"] for item in manifest["reports"]} == {
        "json",
        "markdown",
        "sarif",
        "terminal",
    }

    events_response = client.get(f"/v1/scans/{scan_id}/events")
    assert events_response.status_code == 200
    events = events_response.json()["events"]
    assert events[0]["status"] == "queued"
    assert events[-1]["status"] == "completed"


def test_rule_endpoints_expose_documentation_registry(tmp_path: Path) -> None:
    """Rule registry should power frontend docs links."""
    client, _store = build_test_client(tmp_path)

    list_response = client.get("/v1/rules")
    assert list_response.status_code == 200
    items = list_response.json()["items"]
    assert any(item["rule_id"] == "AST1" for item in items)

    detail_response = client.get("/v1/rules/RP1")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["rule_family"] == "RP"
    assert detail["documentation_url"] == "/v1/rules/RP1"


def test_share_summary_endpoint_returns_compact_payload(tmp_path: Path) -> None:
    """Frontend share action should have a compact backend payload."""
    client, scan_id = create_completed_scan(tmp_path)

    response = client.get(f"/v1/scans/{scan_id}/share-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["headline"] == "Needs Review"
    assert body["findings_preview"][0]["id"] == "AST1"
