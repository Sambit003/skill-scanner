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

"""Tests for deterministic API scan rendering behavior."""

from __future__ import annotations

from skillspector.models import Finding


def test_run_deterministic_scan_invokes_graph_once(monkeypatch) -> None:
    """A multi-format deterministic scan should analyze once and render many times."""
    from skillspector.api.scanner import run_deterministic_scan

    call_count = {"graph": 0, "report": 0, "cleanup": 0}

    async def fake_ainvoke(payload: dict, config: dict):
        call_count["graph"] += 1
        assert payload["input_path"] == "https://github.com/example/repo"
        assert payload["use_llm"] is False
        assert payload["output_format"] == "json"
        assert config["metadata"]["output_format"] == "json"
        return {
            "report_body": '{"kind":"json"}',
            "risk_score": 12,
            "risk_severity": "LOW",
            "risk_recommendation": "SAFE",
            "filtered_findings": [
                Finding(
                    rule_id="SC1",
                    message="test finding",
                    severity="LOW",
                    confidence=0.7,
                    file="requirements.txt",
                    start_line=1,
                    category="Supply Chain",
                    pattern="Unpinned dependency",
                    finding="foo",
                    remediation="pin it",
                )
            ],
            "findings": [],
            "components": ["requirements.txt"],
            "component_metadata": [
                {
                    "path": "requirements.txt",
                    "type": "text",
                    "lines": 1,
                    "executable": False,
                    "size_bytes": 3,
                }
            ],
            "file_cache": {"requirements.txt": "foo"},
            "has_executable_scripts": False,
            "manifest": {"name": "demo"},
            "skill_path": "https://github.com/example/repo",
            "llm_call_log": [],
            "temp_dir_for_cleanup": "C:/tmp/demo",
        }

    def fake_report(state: dict) -> dict:
        call_count["report"] += 1
        fmt = state["output_format"]
        return {"report_body": f"rendered:{fmt}"}

    def fake_cleanup(_result: dict) -> None:
        call_count["cleanup"] += 1

    monkeypatch.setattr("skillspector.api.scanner.graph.ainvoke", fake_ainvoke)
    monkeypatch.setattr("skillspector.api.scanner.report", fake_report)
    monkeypatch.setattr("skillspector.api.scanner.cleanup_result", fake_cleanup)

    summary, reports, findings = __import__("asyncio").run(
        run_deterministic_scan(
            "https://github.com/example/repo",
            ["json", "markdown", "sarif", "terminal"],
        )
    )

    assert call_count == {"graph": 1, "report": 3, "cleanup": 1}
    assert summary["risk_score"] == 12
    assert summary["severity"] == "LOW"
    assert summary["recommendation"] == "SAFE"
    assert summary["findings_count"] == 1
    assert sorted(reports) == ["json", "markdown", "sarif", "terminal"]
    assert reports["json"]["content"] == '{"kind":"json"}'
    assert reports["markdown"]["content"] == "rendered:markdown"
    assert reports["sarif"]["content"] == "rendered:sarif"
    assert reports["terminal"]["content"] == "rendered:terminal"
    assert findings[0]["id"] == "SC1"


def test_run_deterministic_scan_preserves_json_report_when_not_requested(monkeypatch) -> None:
    """The API should still store a JSON report as the canonical machine format."""
    from skillspector.api.scanner import run_deterministic_scan

    async def fake_ainvoke(payload: dict, config: dict):
        assert payload["output_format"] == "markdown"
        assert config["metadata"]["output_format"] == "markdown"
        return {
            "report_body": "rendered:markdown",
            "risk_score": 0,
            "risk_severity": "LOW",
            "risk_recommendation": "SAFE",
            "filtered_findings": [],
            "findings": [],
            "components": [],
            "component_metadata": [],
            "file_cache": {},
            "has_executable_scripts": False,
            "manifest": {"name": "demo"},
            "skill_path": "demo",
            "llm_call_log": [],
        }

    def fake_report(state: dict) -> dict:
        return {"report_body": f"rendered:{state['output_format']}"}

    monkeypatch.setattr("skillspector.api.scanner.graph.ainvoke", fake_ainvoke)
    monkeypatch.setattr("skillspector.api.scanner.report", fake_report)
    monkeypatch.setattr("skillspector.api.scanner.cleanup_result", lambda _result: None)

    _summary, reports, _findings = __import__("asyncio").run(
        run_deterministic_scan("demo", ["markdown"])
    )

    assert sorted(reports) == ["json", "markdown"]
    assert reports["markdown"]["content"] == "rendered:markdown"
    assert reports["json"]["content"] == "rendered:json"
