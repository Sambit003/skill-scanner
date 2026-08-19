from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from backend.domain.models.entities import FindingModel, ScanModel

class ScanRepository:
    """Repository handling all database queries for Scan and Finding entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_scan(
        self,
        asset_target: str,
        repository_key: str,
        asset_type: str,
        scan_scope: str,
        include_readme: bool,
    ) -> ScanModel:
        """Create a new scan record in QUEUED state."""
        scan = ScanModel(
            asset_target=asset_target,
            repository_key=repository_key,
            asset_type=asset_type,
            scan_scope=scan_scope,
            include_readme=include_readme,
            status="QUEUED",
            current_stage="QUEUED",
        )
        self.session.add(scan)
        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    async def get_scan_by_id(self, scan_id: str) -> Optional[ScanModel]:
        """Fetch a single scan by ID."""
        result = await self.session.execute(
            select(ScanModel).where(ScanModel.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def update_stage(self, scan_id: str, stage: str, status: Optional[str] = None) -> None:
        """Update the scan stage and optionally the status."""
        values: Dict[str, Any] = {"current_stage": stage}
        if status:
            values["status"] = status
        if stage == "FETCHING":
            values["started_at"] = datetime.now(timezone.utc)

        await self.session.execute(
            update(ScanModel).where(ScanModel.id == scan_id).values(**values)
        )
        await self.session.commit()

    async def save_scan_success(
        self,
        scan_id: str,
        summary_dict: Dict[str, Any],
        findings_list: List[Dict[str, Any]],
        reports_dict: Dict[str, str],
    ) -> None:
        """Persist findings and mark the scan as COMPLETED."""
        completed_at = datetime.now(timezone.utc)

        # 1. Update Scan Model
        await self.session.execute(
            update(ScanModel)
            .where(ScanModel.id == scan_id)
            .values(
                status="COMPLETED",
                current_stage="COMPLETED",
                risk_score=summary_dict.get("risk_score"),
                severity=summary_dict.get("severity"),
                recommendation=summary_dict.get("recommendation"),
                safe_to_install=summary_dict.get("safe_to_install"),
                findings_count=len(findings_list),
                findings_by_severity=summary_dict.get("findings_by_severity", {}),
                findings_by_category=summary_dict.get("findings_by_category", {}),
                reports_blob=reports_dict,
                completed_at=completed_at,
            )
        )

        # 2. Insert Findings
        for finding in findings_list:
            loc = finding.get("location") or {}
            finding_model = FindingModel(
                scan_id=scan_id,
                rule_id=str(finding.get("id") or "UNKNOWN"),
                title=str(finding.get("pattern") or finding.get("title") or "Finding"),
                severity=str(finding.get("severity") or "UNKNOWN"),
                category=str(finding.get("category") or "Security"),
                description=str(finding.get("description") or finding.get("explanation") or ""),
                remediation=str(finding.get("remediation") or ""),
                file_path=str(loc.get("file") or ""),
                start_line=loc.get("start_line"),
                end_line=loc.get("end_line"),
                code_snippet=str(finding.get("code_snippet") or finding.get("snippet") or ""),
                extra_metadata=finding,
            )
            self.session.add(finding_model)

        await self.session.commit()

    async def save_scan_failure(self, scan_id: str, error_message: str) -> None:
        """Mark scan as FAILED with error message."""
        await self.session.execute(
            update(ScanModel)
            .where(ScanModel.id == scan_id)
            .values(
                status="FAILED",
                current_stage="FAILED",
                error_message=error_message,
                completed_at=datetime.now(timezone.utc),
            )
        )
        await self.session.commit()

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target: Optional[str] = None,
        repository_key: Optional[str] = None,
        scan_scope: Optional[str] = None,
        include_readme: Optional[bool] = None,
    ) -> List[ScanModel]:
        """Fetch historical scans sorted by created_at desc."""
        query = select(ScanModel)
        if target:
            query = query.where(ScanModel.asset_target == target)
        if repository_key:
            query = query.where(ScanModel.repository_key == repository_key)
        if scan_scope:
            query = query.where(ScanModel.scan_scope == scan_scope)
        if include_readme is not None:
            query = query.where(ScanModel.include_readme == include_readme)
        result = await self.session.execute(
            query.order_by(desc(ScanModel.created_at)).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def get_findings_for_scan(
        self, scan_id: str, severity: Optional[str] = None
    ) -> List[FindingModel]:
        """Fetch all findings for a given scan with optional severity filter."""
        query = select(FindingModel).where(FindingModel.scan_id == scan_id)
        if severity:
            query = query.where(FindingModel.severity == severity.upper())
        result = await self.session.execute(query)
        return list(result.scalars().all())
