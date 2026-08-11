from fastapi import APIRouter, Depends
from typing import List
from pydantic import BaseModel
from backend.services.scanner_client import ScannerClient

router = APIRouter(prefix="/rules", tags=["Rules"])

class RuleDocResponse(BaseModel):
    rule_id: str
    rule_family: str
    title: str
    category: str
    description: str
    remediation: str
    documentation_url: str

class RuleListResponse(BaseModel):
    items: List[RuleDocResponse]


def get_scanner_client() -> ScannerClient:
    return ScannerClient()


@router.get("", response_model=RuleListResponse)
async def list_rules(client: ScannerClient = Depends(get_scanner_client)):
    """List all supported security and safety scanning rules."""
    docs = await client.list_rules()
    return RuleListResponse(items=[RuleDocResponse(**doc.model_dump()) for doc in docs])

@router.get("/{rule_id}", response_model=RuleDocResponse)
async def get_rule(rule_id: str, client: ScannerClient = Depends(get_scanner_client)):
    """Retrieve detailed documentation and remediation instructions for a specific rule."""
    doc = await client.get_rule(rule_id)
    return RuleDocResponse(**doc.model_dump())
