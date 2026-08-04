from fastapi import APIRouter
from typing import List, Dict, Any
from pydantic import BaseModel
from scanner_engine.engine.plugins.agent_skills.presentation import (
    all_rule_docs,
    get_rule_doc,
)

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

@router.get("", response_model=RuleListResponse)
async def list_rules():
    """List all supported security and safety scanning rules."""
    docs = all_rule_docs()
    return RuleListResponse(items=[RuleDocResponse(**doc) for doc in docs])

@router.get("/{rule_id}", response_model=RuleDocResponse)
async def get_rule(rule_id: str):
    """Retrieve detailed documentation and remediation instructions for a specific rule."""
    doc = get_rule_doc(rule_id)
    return RuleDocResponse(**doc)
