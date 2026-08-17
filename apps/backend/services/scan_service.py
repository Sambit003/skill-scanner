from typing import List, Optional
from backend.domain.models.schemas import (
    FindingResponse,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanListItemResponse,
    ScanResponse,
)
from backend.repositories.scan_repository import ScanRepository
from backend.services.score_visibility import redact_report_content, visible_risk_score
from backend.workers.scan_worker import run_asset_scan_task

class ScanService:
    """Service layer orchestrating scan lifecycles and business workflows."""

    def __init__(self, repository: ScanRepository):
        self.repo = repository

    async def initiate_scan(self, request: ScanCreateRequest) -> ScanResponse:
        """Create a scan in QUEUED state and dispatch to Celery worker."""
        scan = await self.repo.create_scan(
            asset_target=request.target,
            asset_type=request.asset_type,
        )

        # Dispatch async task to Celery
        try:
            run_asset_scan_task.delay(
                scan_id=scan.id,
                target=request.target,
                asset_type=request.asset_type,
            )
        except Exception:
            # Fallback to local synchronous/background execution if Celery broker is offline in dev
            import asyncio
            from backend.workers.scan_worker import _execute_scan_pipeline
            asyncio.create_task(
                _execute_scan_pipeline(
                    scan_id=scan.id,
                    target=request.target,
                    asset_type=request.asset_type,
                )
            )

        return ScanResponse(
            id=scan.id,
            asset_target=scan.asset_target,
            asset_type=scan.asset_type,
            status=scan.status,
            current_stage=scan.current_stage,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
        )

    async def get_scan_details(self, scan_id: str) -> Optional[ScanDetailResponse]:
        """Fetch full scan detail including summary and reports metadata."""
        scan = await self.repo.get_scan_by_id(scan_id)
        if not scan:
            return None

        findings_models = await self.repo.get_findings_for_scan(scan_id)
        findings = [FindingResponse.model_validate(f) for f in findings_models]

        summary = None
        available_reports: List[str] = []
        report_downloads = []
        is_terminal = scan.status in ["COMPLETED", "FAILED", "CANCELED"]

        if scan.reports_blob:
            available_reports = list(scan.reports_blob.keys())
            report_downloads = [
                {"format": fmt, "url": f"/v1/scans/{scan.id}/reports/{fmt}"}
                for fmt in available_reports
            ]

        findings_by_severity = scan.findings_by_severity or {}
        findings_by_category = scan.findings_by_category or {}
        findings_count = scan.findings_count or len(findings)

        severity_breakdown = [
            {"label": k, "count": v} for k, v in findings_by_severity.items()
        ]
        category_breakdown = [
            {"label": k, "count": v} for k, v in findings_by_category.items()
        ]

        duration_seconds = None
        duration_ms = None
        if scan.started_at and scan.completed_at:
            duration_seconds = max(0.0, (scan.completed_at - scan.started_at).total_seconds())
            duration_ms = int(duration_seconds * 1000)

        display_target = scan.asset_target.split("/")[-1].replace(".git", "") if scan.asset_target else scan.asset_target

        headline = "Unsafe to install" if scan.safe_to_install is False else ("Safe to install" if scan.safe_to_install is True else None)
        summary_text = None
        if scan.status == "COMPLETED":
            if findings_count == 0:
                summary_text = "No deterministic findings were detected in this scan."
            else:
                cat_count = len(category_breakdown)
                summary_text = f"This scan detected {findings_count} finding{'s' if findings_count != 1 else ''} across {cat_count} categor{'ies' if cat_count != 1 else 'y'}."

        links = {
            "self": f"/v1/scans/{scan.id}",
            "findings": f"/v1/scans/{scan.id}/findings",
            "reports": f"/v1/scans/{scan.id}/reports",
            "events": f"/v1/scans/{scan.id}/events",
            "share_summary": f"/v1/scans/{scan.id}/summary",
        }

        return ScanDetailResponse(
            id=scan.id,
            scan_id=scan.id,
            asset_target=scan.asset_target,
            target=scan.asset_target,
            display_target=display_target,
            asset_type=scan.asset_type,
            status=scan.status,
            current_stage=scan.current_stage,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_seconds=duration_seconds,
            duration_ms=duration_ms,
            error_message=scan.error_message,
            error=scan.error_message,
            risk_score=visible_risk_score(scan.risk_score),
            severity=scan.severity,
            recommendation=scan.recommendation,
            safe_to_install=scan.safe_to_install,
            primary_verdict=headline,
            headline=headline,
            summary=summary_text,
            findings_count=findings_count,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            findings=findings,
            available_reports=available_reports,
            report_downloads=report_downloads,
            links=links,
            is_terminal=is_terminal,
        )

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target: Optional[str] = None,
    ) -> List[ScanListItemResponse]:
        """List historical scans."""
        scans = await self.repo.list_scans(limit=limit, offset=offset, target=target)
        items = []
        for scan in scans:
            duration_seconds = None
            if scan.started_at and scan.completed_at:
                duration_seconds = max(0.0, (scan.completed_at - scan.started_at).total_seconds())

            display_target = scan.asset_target.split("/")[-1].replace(".git", "") if scan.asset_target else scan.asset_target
            headline = "Unsafe to install" if scan.safe_to_install is False else ("Safe to install" if scan.safe_to_install is True else None)
            findings_count = scan.findings_count or 0
            summary = None
            if scan.status == "COMPLETED":
                summary = (
                    "No deterministic findings were detected in this scan."
                    if findings_count == 0
                    else f"This scan detected {findings_count} finding{'s' if findings_count != 1 else ''}."
                )

            items.append(ScanListItemResponse(
                id=scan.id,
                asset_target=scan.asset_target,
                asset_type=scan.asset_type,
                status=scan.status,
                current_stage=scan.current_stage,
                created_at=scan.created_at,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                error_message=scan.error_message,
                display_target=display_target,
                duration_seconds=duration_seconds,
                is_terminal=scan.status in ["COMPLETED", "FAILED", "CANCELED"],
                risk_score=visible_risk_score(scan.risk_score),
                severity=scan.severity,
                recommendation=scan.recommendation,
                safe_to_install=scan.safe_to_install,
                headline=headline,
                summary=summary,
                findings_count=findings_count,
            ))
        return items

    async def get_report_content(self, scan_id: str, report_format: str) -> Optional[str]:
        """Fetch raw generated report content by format."""
        scan = await self.repo.get_scan_by_id(scan_id)
        if not scan or not scan.reports_blob:
            return None
        fmt = report_format.lower()
        content = scan.reports_blob.get(fmt)
        if content is None:
            return None
        return redact_report_content(content, fmt)
