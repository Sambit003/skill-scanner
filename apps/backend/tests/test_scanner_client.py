from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.services.scanner_client import ScannerClient, ScannerClientError


def make_executable(tmp_path: Path, body: str) -> str:
    executable = tmp_path / "fake-scanner"
    executable.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    executable.chmod(0o755)
    return str(executable)


def success_payload() -> dict[str, object]:
    return {
        "protocol_version": "1",
        "ok": True,
        "result": {
            "kind": "scan",
            "summary": {
                "risk_score": 90,
                "severity": "CRITICAL",
                "recommendation": "DO_NOT_INSTALL",
                "safe_to_install": False,
                "findings_count": 1,
                "findings_by_severity": {"CRITICAL": 1},
                "findings_by_category": {"Security": 1},
                "scanner_version": "test",
                "scan_mode": "deterministic",
            },
            "findings": [{"id": "TEST-1"}],
            "reports": {
                "json": {"content": "{}", "content_type": "application/json"}
            },
        },
    }


@pytest.mark.asyncio
async def test_high_risk_result_is_not_treated_as_process_failure(tmp_path: Path) -> None:
    payload = json.dumps(success_payload())
    executable = make_executable(
        tmp_path,
        f"import sys\nsys.stdin.read()\nprint({payload!r})\n",
    )

    result = await ScannerClient(executable=executable, timeout_seconds=5).scan(
        target="fixture",
        asset_type="agent_skill",
        output_formats=["json"],
    )

    assert result.summary.risk_score == 90
    assert result.summary.safe_to_install is False


@pytest.mark.asyncio
async def test_scanner_summary_accepts_evidence_gated_scores(tmp_path: Path) -> None:
    response = success_payload()
    summary = response["result"]["summary"]
    summary["vulnerability_score"] = 75
    summary["exposure_score"] = 42.5
    payload = json.dumps(response)
    executable = make_executable(
        tmp_path,
        f"import sys\nsys.stdin.read()\nprint({payload!r})\n",
    )

    result = await ScannerClient(executable=executable, timeout_seconds=5).scan(
        target="fixture",
        asset_type="agent_skill",
        output_formats=["json"],
    )

    assert result.summary.vulnerability_score == 75
    assert result.summary.exposure_score == 42.5


@pytest.mark.asyncio
async def test_nonzero_machine_error_is_reported(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "protocol_version": "1",
            "ok": False,
            "error": {"code": "SCAN_FAILED", "message": "fixture failure"},
        }
    )
    executable = make_executable(
        tmp_path,
        f"import sys\nsys.stdin.read()\nprint({payload!r})\nraise SystemExit(3)\n",
    )

    with pytest.raises(ScannerClientError, match="fixture failure") as exc_info:
        await ScannerClient(executable=executable, timeout_seconds=5).scan(
            target="fixture",
            asset_type="agent_skill",
            output_formats=["json"],
        )

    assert exc_info.value.code == "SCAN_FAILED"


@pytest.mark.asyncio
async def test_malformed_success_response_is_rejected(tmp_path: Path) -> None:
    executable = make_executable(
        tmp_path,
        "import sys\nsys.stdin.read()\nprint('{\"ok\": true}')\n",
    )

    with pytest.raises(ScannerClientError, match="violated protocol v1"):
        await ScannerClient(executable=executable, timeout_seconds=5).scan(
            target="fixture",
            asset_type="agent_skill",
            output_formats=["json"],
        )


@pytest.mark.asyncio
async def test_process_timeout_is_enforced(tmp_path: Path) -> None:
    executable = make_executable(
        tmp_path,
        "import sys, time\nsys.stdin.read()\ntime.sleep(1)\n",
    )

    with pytest.raises(ScannerClientError, match="execution timeout"):
        await ScannerClient(executable=executable, timeout_seconds=0.05).scan(
            target="fixture",
            asset_type="agent_skill",
            output_formats=["json"],
        )


@pytest.mark.asyncio
async def test_rule_registry_uses_the_same_process_boundary(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "protocol_version": "1",
            "ok": True,
            "result": {
                "kind": "rules",
                "items": [
                    {
                        "rule_id": "P1",
                        "rule_family": "P",
                        "title": "Instruction Override",
                        "category": "Prompt Injection",
                        "description": "description",
                        "remediation": "remediation",
                        "documentation_url": "/v1/rules/P1",
                    }
                ],
            },
        }
    )
    executable = make_executable(
        tmp_path,
        f"import sys\nsys.stdin.read()\nprint({payload!r})\n",
    )

    rules = await ScannerClient(executable=executable, timeout_seconds=5).list_rules()

    assert [rule.rule_id for rule in rules] == ["P1"]
