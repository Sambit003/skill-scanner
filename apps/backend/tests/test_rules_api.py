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
