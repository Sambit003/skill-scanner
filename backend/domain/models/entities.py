import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from backend.core.database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    asset_target = Column(String(512), nullable=False)
    asset_type = Column(String(64), nullable=False, default="agent_skill", index=True)
    status = Column(String(32), nullable=False, default="QUEUED", index=True)
    
    # State tracking: QUEUED -> FETCHING -> DETER_SCAN -> COMPLETED / FAILED
    current_stage = Column(String(32), nullable=True)
    
    # Metric aggregates
    risk_score = Column(Integer, nullable=True)
    severity = Column(String(32), nullable=True)
    recommendation = Column(String(64), nullable=True)
    safe_to_install = Column(Boolean, nullable=True)
    findings_count = Column(Integer, default=0)
    
    # Summary JSON blobs
    findings_by_severity = Column(JSON, default=dict)
    findings_by_category = Column(JSON, default=dict)
    reports_blob = Column(JSON, default=dict)
    
    # Timing & errors
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")

class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    rule_id = Column(String(128), nullable=False, index=True)
    title = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    category = Column(String(256), nullable=False, index=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    file_path = Column(Text, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    
    extra_metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    scan = relationship("ScanModel", back_populates="findings")
