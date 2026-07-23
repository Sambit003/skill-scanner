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

"""Tests for API hardening and runtime guardrails."""

from __future__ import annotations

import os
import time
from pathlib import Path

from .test_api_jobs import build_test_client


def test_cors_preflight_allows_local_nextjs_origin(tmp_path: Path) -> None:
    """API should allow local Next.js origins for browser preflight."""
    client, _store = build_test_client(tmp_path)

    response = client.options(
        "/v1/scans",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_create_scan_rejects_disallowed_target_host(tmp_path: Path) -> None:
    """Queueing should fail early for SSRF-disallowed targets."""
    client, _store = build_test_client(tmp_path)

    response = client.post(
        "/v1/scans",
        json={
            "target": "https://evil-attacker.com/payload.md",
            "mode": "deterministic",
            "formats": ["json"],
        },
    )

    assert response.status_code == 400
    assert "allowed hosts list" in response.json()["detail"]


def test_create_scan_normalizes_duplicate_formats(tmp_path: Path) -> None:
    """Duplicate formats should be deduplicated before persistence."""
    client, _store = build_test_client(tmp_path)

    create = client.post(
        "/v1/scans",
        json={
            "target": str(tmp_path),
            "mode": "deterministic",
            "formats": ["json", "json", "markdown"],
        },
    )

    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    status_response = client.get(f"/v1/scans/{scan_id}")
    assert status_response.status_code == 200
    assert status_response.json()["requested_formats"] == ["json", "markdown"]


def test_worker_marks_timeout_as_failed(monkeypatch, tmp_path: Path) -> None:
    """Worker should fail scans that exceed configured timeout."""
    from skillspector.api.worker import process_next_scan_once

    _client, store = build_test_client(tmp_path)
    created = store.create_scan(
        target="https://github.com/example/repo",
        mode="deterministic",
        requested_formats=["json"],
    )

    async def slow_run(_target: str, _formats: list[str]):
        await __import__("asyncio").sleep(0.05)
        return {}, {}, []

    monkeypatch.setattr("skillspector.api.worker.run_deterministic_scan", slow_run)

    processed = __import__("asyncio").run(process_next_scan_once(store, timeout_seconds=0.01))

    assert processed is True
    scan = store.get_scan(created["scan_id"])
    assert scan is not None
    assert scan["status"] == "failed"
    assert "timeout" in (scan["error"] or "")


def test_cleanup_stale_workdirs_removes_old_skillspector_dirs(tmp_path: Path) -> None:
    """Only stale skillspector temp directories under work_dir should be removed."""
    from skillspector.api.guardrails import cleanup_stale_workdirs

    stale = tmp_path / "skillspector_old"
    fresh = tmp_path / "skillspector_new"
    unrelated = tmp_path / "frontend-cache"
    stale.mkdir()
    fresh.mkdir()
    unrelated.mkdir()

    old_time = time.time() - 7200
    os.utime(stale, (old_time, old_time))

    removed = cleanup_stale_workdirs(str(tmp_path), max_age_seconds=3600)

    assert removed == 1
    assert not stale.exists()
    assert fresh.exists()
    assert unrelated.exists()
