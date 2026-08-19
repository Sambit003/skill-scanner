from typing import List, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from backend.api.dependencies.database import get_scan_service
from backend.domain.models.schemas import (
    FindingResponse,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanFindingsResponse,
    ScanListItemResponse,
    ScanResponse,
)
from backend.services.scan_service import ScanService
from backend.services.score_visibility import visible_risk_score

router = APIRouter(prefix="/scans", tags=["Scans"])

MEDIA_TYPES = {
    "json": "application/json",
    "sarif": "application/sarif+json",
    "markdown": "text/markdown; charset=utf-8",
    "terminal": "text/plain; charset=utf-8",
}

@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    request: ScanCreateRequest,
    service: ScanService = Depends(get_scan_service),
):
    """Initiate an asynchronous asset scan."""
    return await service.initiate_scan(request)

@router.get("", response_model=List[ScanListItemResponse])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    target: Optional[str] = Query(default=None, description="Exact skill target to retrieve history for"),
    repository_key: Optional[str] = Query(default=None, description="Normalized repository identity to retrieve history for"),
    scan_scope: Optional[Literal["skill_files", "skill_folders", "repository"]] = Query(default=None),
    include_readme: Optional[bool] = Query(default=None),
    service: ScanService = Depends(get_scan_service),
):
    """List historical asset scans."""
    return await service.list_scans(
        limit=limit,
        offset=offset,
        target=target,
        repository_key=repository_key,
        scan_scope=scan_scope,
        include_readme=include_readme,
    )

@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_by_id(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
):
    """Get scan status, metrics, and findings by scan ID."""
    scan = await service.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return scan

@router.get("/{scan_id}/findings", response_model=ScanFindingsResponse)
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(default=None, description="Filter by severity (e.g. CRITICAL, HIGH)"),
    category: Optional[str] = Query(default=None, description="Filter by category"),
    q: Optional[str] = Query(default=None, description="Search term across title and description"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=500, ge=1, le=1000),
    service: ScanService = Depends(get_scan_service),
):
    """Retrieve findings for a specific scan."""
    scan = await service.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    
    findings = scan.findings
    if severity and severity.upper() != "ALL":
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    if category and category.upper() != "ALL":
        findings = [f for f in findings if f.category.upper() == category.upper()]
    if q:
        q_lower = q.lower()
        findings = [
            f for f in findings
            if q_lower in (f.title or "").lower() or q_lower in (f.file_path or "").lower()
        ]

    total = len(findings)
    start_idx = (page - 1) * page_size
    paged_findings = findings[start_idx : start_idx + page_size]

    return ScanFindingsResponse(
        scan_id=scan_id,
        status=scan.status,
        total=total,
        page=page,
        page_size=page_size,
        findings=paged_findings,
    )

@router.get("/{scan_id}/reports")
async def get_scan_reports_manifest(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
):
    """Retrieve available report downloads manifest."""
    scan = await service.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    reports = [
        {"format": fmt, "url": f"/v1/scans/{scan_id}/reports/{fmt}"}
        for fmt in (scan.available_reports or ["json", "sarif", "markdown", "terminal"])
    ]
    return {
        "scan_id": scan_id,
        "scan_scope": scan.scan_scope,
        "include_readme": scan.include_readme,
        "reports": reports,
    }


@router.get("/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
):
    """Retrieve execution lifecycle events for a scan."""
    scan = await service.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    events = [
        {
            "id": 1,
            "scan_id": scan_id,
            "status": scan.status,
            "message": f"Scan transitioned to {scan.status}",
            "created_at": scan.created_at.isoformat() if scan.created_at else "",
        }
    ]
    return {"scan_id": scan_id, "events": events}


@router.get("/{scan_id}/share-summary")
async def get_scan_share_summary(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
):
    """Retrieve quick share summary card metadata."""
    scan = await service.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "headline": scan.headline,
        "summary": scan.summary,
        "risk_score": visible_risk_score(scan.risk_score),
        "severity": scan.severity,
        "recommendation": "Review high-confidence findings before execution.",
        "target": scan.target,
        "scan_scope": scan.scan_scope,
        "include_readme": scan.include_readme,
        "findings_preview": scan.findings[:5] if scan.findings else [],
    }


@router.get("/{scan_id}/reports/{format}")
async def get_scan_report(
    scan_id: str,
    format: str,
    service: ScanService = Depends(get_scan_service),
):
    """Download or view a formatted report (json, sarif, markdown, terminal)."""
    fmt = format.lower()
    if fmt not in MEDIA_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{format}'. Supported formats: {list(MEDIA_TYPES.keys())}",
        )

    content = await service.get_report_content(scan_id, fmt)
    if content is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report format '{format}' not found or scan is not completed yet",
        )

    return Response(content=content, media_type=MEDIA_TYPES[fmt])
