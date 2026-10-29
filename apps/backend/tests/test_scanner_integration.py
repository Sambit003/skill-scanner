from __future__ import annotations

import os
from pathlib import Path

import pytest

from backend.services.scanner_client import ScannerClient


@pytest.mark.asyncio
async def test_backend_calls_real_go_scanner() -> None:
    executable = os.environ.get("SCAN_KERNEL_EXECUTABLE")
    if not executable:
        pytest.skip("real scanner integration is run by the backend:integration Moon task")
    fixture = Path(__file__).parents[3] / "packages" / "scan_kernel" / "testdata" / "malicious_skill"

    client = ScannerClient(executable=executable, timeout_seconds=10)
    result = await client.scan(
        target=str(fixture),
        asset_type="skill",
        output_formats=["json", "sarif"],
    )
    rules = await client.list_rules()

    assert result.kind == "scan"
    assert result.summary.safe_to_install is False
    assert result.summary.findings_count >= 2
    assert set(result.reports) == {"json", "sarif"}
    # The request opts into capabilities; the fixture runs a shell command.
    assert result.capabilities is not None
    assert any(capability.rule_id == "AST4" for capability in result.capabilities)
    assert any(rule.rule_id == "P1" for rule in rules)
