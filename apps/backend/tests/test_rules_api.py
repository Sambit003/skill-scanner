from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.api.v1.routers.rules import get_rule
from backend.services.scanner_client import ScannerClientError


class MissingRuleClient:
    async def get_rule(self, rule_id: str):
        raise ScannerClientError("rule documentation is not available", code="INVALID_REQUEST")


class FailedScannerClient:
    async def get_rule(self, rule_id: str):
        raise ScannerClientError("scanner unavailable", code="SCAN_FAILED")


@pytest.mark.asyncio
async def test_missing_rule_is_reported_as_unavailable() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await get_rule("missing-rule", client=MissingRuleClient())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Rule documentation is not available"


@pytest.mark.asyncio
async def test_scanner_failure_is_reported_as_bad_gateway() -> None:
    with pytest.raises(HTTPException) as exc_info:
        await get_rule("TR3", client=FailedScannerClient())

    assert exc_info.value.status_code == 502
    assert exc_info.value.detail == "Scanner engine could not provide rule metadata"


class SuccessfulRuleClient:
    async def get_rule(self, rule_id: str):
        from backend.domain.models.scanner_protocol import ScannerFrameworkRefs, ScannerRuleDoc

        return ScannerRuleDoc(
            rule_id="EA4",
            rule_family="EA",
            title="Unbounded Resource Access",
            category="Resource Management",
            description="Unbounded loops.",
            remediation="Add rate limits.",
            documentation_url="/v1/rules/EA4",
            frameworks=ScannerFrameworkRefs(
                mapping_version="2026.09-1",
                owasp_agentic=["AST03"],
                owasp_llm=["LLM03:2026", "LLM06:2026"],
                nist_gai_risks=["Information Security"],
                nist_rmf=["MEASURE 2.7"],
            ),
        )


@pytest.mark.asyncio
async def test_get_rule_returns_frameworks() -> None:
    doc = await get_rule("EA4", client=SuccessfulRuleClient())
    assert doc.rule_id == "EA4"
    assert doc.frameworks is not None
    assert doc.frameworks.mapping_version == "2026.09-1"
    assert doc.frameworks.owasp_llm == ["LLM03:2026", "LLM06:2026"]
    assert doc.frameworks.nist_rmf == ["MEASURE 2.7"]

