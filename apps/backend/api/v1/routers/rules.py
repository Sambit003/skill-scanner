from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel
from backend.services.scanner_client import ScannerClient, ScannerClientError

router = APIRouter(prefix="/rules", tags=["Rules"])

class FrameworkRefsResponse(BaseModel):
    mapping_version: str
    owasp_agentic: List[str]
    owasp_llm: List[str]
    nist_gai_risks: List[str]
    nist_rmf: List[str]

class RuleDocResponse(BaseModel):
    rule_id: str
    rule_family: str
    title: str
    category: str
    description: str
    remediation: str
    documentation_url: str
    frameworks: Optional[FrameworkRefsResponse] = None


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
    try:
        doc = await client.get_rule(rule_id)
    except ScannerClientError as exc:
        if exc.code == "INVALID_REQUEST":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Rule documentation is not available",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Scanner engine could not provide rule metadata",
        ) from exc
    return RuleDocResponse(**doc.model_dump())
