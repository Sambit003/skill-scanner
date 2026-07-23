"""FastAPI app entrypoint for the SkillSpector backend."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.cors import CORSMiddleware

from skillspector import __version__
from skillspector.logging_config import get_logger

from .byok import AgentReviewSecret, agent_review_secret_vault
from .config import load_api_config
from .guardrails import cleanup_stale_workdirs, normalize_formats, validate_scan_target
from .openrouter import list_openrouter_models
from .presentation import all_rule_docs, enrich_finding, enrich_scan, get_rule_doc
from .schemas import (
    AgentReviewReportResponse,
    CreateScanRequest,
    CreateScanResponse,
    OpenRouterModelsResponse,
    FindingResponse,
    HealthResponse,
    ReportFormat,
    RuleDocResponse,
    RuleListResponse,
    ScanEventsResponse,
    ScanFindingsResponse,
    ScanListResponse,
    ScanReportsManifestResponse,
    ScanSummaryResponse,
    VersionResponse,
)
from .store import ApiStore
from .worker import process_next_scan_once

SERVICE_NAME = "skillspector-api"
logger = get_logger(__name__)

REPORT_FILE_EXTENSIONS: dict[str, str] = {
    "json": "json",
    "markdown": "md",
    "sarif": "sarif",
    "terminal": "txt",
}


def _get_existing_scan_or_404(store: ApiStore, scan_id: str) -> dict[str, Any]:
    """Load a scan or raise 404."""
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


def _require_completed_scan(scan: dict[str, Any]) -> None:
    """Reject report/finding access until a scan is completed."""
    if scan["status"] != "completed":
        raise HTTPException(
            status_code=409,
            detail=f"scan not completed: current status is {scan['status']}",
        )


def _reports_manifest(scan: dict[str, Any]) -> dict[str, Any]:
    """Return explicit report manifest for a scan."""
    enriched = enrich_scan(scan)
    return {
        "scan_id": scan["scan_id"],
        "reports": enriched["report_downloads"],
    }


def _report_download_filename(scan_id: str, fmt: str) -> str:
    """Build a stable attachment filename for one exported report."""
    extension = REPORT_FILE_EXTENSIONS.get(fmt, fmt)
    return f"skillspector-{scan_id}.{extension}"


def _process_next_scan_once_sync(store: ApiStore, timeout_seconds: float) -> bool:
    """Run one async worker iteration in a background thread."""
    return asyncio.run(
        process_next_scan_once(
            store,
            timeout_seconds=timeout_seconds,
        )
    )


def create_app(api_config=None) -> FastAPI:
    """Create a configured FastAPI app instance."""
    resolved_config = api_config or load_api_config()
    store = ApiStore(resolved_config.db_path)
    store.init_db()

    async def embedded_worker_loop() -> None:
        """Continuously claim and process queued scans inside the API process."""
        logger.info("Embedded worker loop started for db=%s", resolved_config.db_path)
        while True:
            try:
                processed = await asyncio.to_thread(
                    _process_next_scan_once_sync,
                    store,
                    resolved_config.max_scan_timeout_seconds,
                )
                if not processed:
                    await asyncio.sleep(resolved_config.worker_poll_seconds)
            except asyncio.CancelledError:
                logger.info("Embedded worker loop stopped")
                raise
            except Exception:
                logger.exception("Embedded worker loop crashed; retrying")
                await asyncio.sleep(resolved_config.worker_poll_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run startup/shutdown hooks, including the optional embedded worker."""
        worker_task: asyncio.Task[None] | None = None
        recovered = app.state.store.fail_running_scans(
            "scan interrupted by service restart before completion",
        )
        if recovered:
            logger.warning("Recovered %d interrupted running scan(s) on startup", recovered)
        if resolved_config.embedded_worker_enabled:
            worker_task = asyncio.create_task(
                embedded_worker_loop(),
                name="skillspector-embedded-worker",
            )
            app.state.worker_task = worker_task
        try:
            yield
        finally:
            if worker_task is not None:
                worker_task.cancel()
                with suppress(asyncio.CancelledError):
                    await worker_task

    app = FastAPI(
        title="SkillSpector API",
        description=(
            "Deterministic backend for SkillSpector scan jobs, findings, rule documentation, "
            "and report downloads."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.state.api_config = resolved_config
    app.state.store = store
    cleanup_stale_workdirs(
        resolved_config.work_dir,
        max_age_seconds=resolved_config.max_temp_dir_age_seconds,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved_config.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["content-disposition"],
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Return basic service health and runtime config."""
        return HealthResponse(
            status="ok",
            service=SERVICE_NAME,
            scanner_version=__version__,
            data_dir=resolved_config.data_dir,
            work_dir=resolved_config.work_dir,
        )

    @app.get("/v1/version", response_model=VersionResponse)
    async def version() -> VersionResponse:
        """Return the API and scanner version information."""
        return VersionResponse(service=SERVICE_NAME, scanner_version=__version__)

    @app.post("/v1/scans", response_model=CreateScanResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_scan(request: CreateScanRequest) -> CreateScanResponse:
        """Queue a new deterministic scan job."""
        validate_scan_target(request.target, max_target_length=resolved_config.max_target_length)
        normalized_formats = normalize_formats(request.formats)
        if request.agent_review_api_key and not request.agent_review_enabled:
            raise HTTPException(
                status_code=400,
                detail="agent_review_api_key requires agent_review_enabled=true",
            )
        if request.agent_review_api_key and request.agent_review_provider != "openrouter":
            raise HTTPException(
                status_code=400,
                detail="BYOK agent review currently supports only agent_review_provider='openrouter'",
            )
        if request.agent_review_api_key and not resolved_config.embedded_worker_enabled:
            raise HTTPException(
                status_code=400,
                detail="BYOK agent review requires the embedded worker to be enabled",
            )
        created = app.state.store.create_scan(
            target=request.target,
            mode=request.mode,
            requested_formats=normalized_formats,
            agent_review_enabled=request.agent_review_enabled,
            agent_review_provider=request.agent_review_provider,
            agent_review_skill=request.agent_review_skill,
            agent_review_prompt=request.agent_review_prompt,
            agent_review_model=request.agent_review_model,
        )
        if request.agent_review_api_key:
            agent_review_secret_vault.put(
                created["scan_id"],
                AgentReviewSecret(
                    provider=request.agent_review_provider or "openrouter",
                    api_key=request.agent_review_api_key,
                ),
            )
        return CreateScanResponse(**created)

    @app.get("/v1/scans", response_model=ScanListResponse)
    async def list_scans(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
        status_filter: str | None = Query(default=None, alias="status"),
        mode: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        target: str | None = Query(default=None),
        scan_id: str | None = Query(default=None),
        sort: str = Query(default="created_at_desc"),
    ) -> ScanListResponse:
        """List scans for the scans index screen."""
        result = app.state.store.list_scans(
            page=page,
            page_size=page_size,
            status=status_filter,
            mode=mode,
            severity=severity,
            target=target,
            scan_id=scan_id,
            sort=sort,
        )
        return ScanListResponse(
            page=result["page"],
            page_size=result["page_size"],
            total=result["total"],
            items=[
                ScanSummaryResponse(
                    **enrich_scan(
                        scan,
                        default_poll_after_ms=resolved_config.default_poll_after_ms,
                    )
                )
                for scan in result["items"]
            ],
        )

    @app.get("/v1/scans/{scan_id}", response_model=ScanSummaryResponse)
    async def get_scan(scan_id: str) -> ScanSummaryResponse:
        """Fetch one scan job by ID."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        return ScanSummaryResponse(
            **enrich_scan(scan, default_poll_after_ms=resolved_config.default_poll_after_ms)
        )

    @app.get("/v1/scans/{scan_id}/findings", response_model=ScanFindingsResponse)
    async def get_scan_findings(
        scan_id: str,
        severity: str | None = Query(default=None),
        category: str | None = Query(default=None),
        rule_family: str | None = Query(default=None),
        file: str | None = Query(default=None),
        q: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=500),
        sort: str = Query(default="severity_desc"),
    ) -> ScanFindingsResponse:
        """Fetch normalized findings for one completed scan."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        _require_completed_scan(scan)
        result = app.state.store.get_scan_findings(
            scan_id,
            severity=severity,
            category=category,
            rule_family_filter=rule_family,
            file_query=file,
            q=q,
            page=page,
            page_size=page_size,
            sort=sort,
        )
        if result is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return ScanFindingsResponse(
            scan_id=scan_id,
            status=result["status"],
            total=result["total"],
            page=result["page"],
            page_size=result["page_size"],
            findings=[FindingResponse(**enrich_finding(finding)) for finding in result["findings"]],
        )

    @app.get("/v1/scans/{scan_id}/reports", response_model=ScanReportsManifestResponse)
    async def get_scan_reports_manifest(scan_id: str) -> ScanReportsManifestResponse:
        """Return available report URLs for one completed scan."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        _require_completed_scan(scan)
        return ScanReportsManifestResponse(**_reports_manifest(scan))

    @app.get("/v1/scans/{scan_id}/reports/{fmt}")
    async def get_scan_report(scan_id: str, fmt: ReportFormat):
        """Fetch one stored report for a completed scan."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        _require_completed_scan(scan)
        report = app.state.store.get_scan_report(scan_id, fmt)
        if report is None:
            raise HTTPException(status_code=404, detail=f"report not found for format: {fmt}")
        attachment_name = _report_download_filename(scan_id, fmt)
        headers = {"Content-Disposition": f'attachment; filename="{attachment_name}"'}

        if fmt in {"json", "sarif"}:
            return JSONResponse(
                content=json.loads(report["content"]),
                media_type=report["content_type"],
                headers=headers,
            )
        return PlainTextResponse(
            content=report["content"],
            media_type=report["content_type"],
            headers=headers,
        )

    @app.get("/v1/scans/{scan_id}/events", response_model=ScanEventsResponse)
    async def get_scan_events(scan_id: str) -> ScanEventsResponse:
        """Return timeline events for one scan."""
        _scan = _get_existing_scan_or_404(app.state.store, scan_id)
        events = app.state.store.get_scan_events(scan_id) or []
        return ScanEventsResponse(scan_id=scan_id, events=events)

    @app.get("/v1/scans/{scan_id}/agent-review", response_model=AgentReviewReportResponse)
    async def get_scan_agent_review(scan_id: str) -> AgentReviewReportResponse:
        """Return the bounded agent review for one completed scan."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        _require_completed_scan(scan)
        report = app.state.store.get_agent_review_report(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return AgentReviewReportResponse(scan_id=scan_id, **report)

    @app.get("/v1/providers/openrouter/models", response_model=OpenRouterModelsResponse)
    async def get_openrouter_models(refresh: bool = Query(default=False)) -> OpenRouterModelsResponse:
        """Return a normalized OpenRouter catalog for BYOK model selection."""
        try:
            payload = await asyncio.to_thread(list_openrouter_models, force_refresh=refresh)
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"could not load OpenRouter models: {exc}",
            ) from exc
        return OpenRouterModelsResponse(**payload)

    @app.get("/v1/scans/{scan_id}/share-summary")
    async def get_scan_share_summary(scan_id: str) -> dict[str, Any]:
        """Return a compact share-ready payload for the frontend."""
        scan = _get_existing_scan_or_404(app.state.store, scan_id)
        _require_completed_scan(scan)
        enriched_scan = enrich_scan(scan)
        findings_result = app.state.store.get_scan_findings(scan_id, page=1, page_size=10)
        findings = findings_result["findings"] if findings_result is not None else []
        return {
            "scan_id": scan_id,
            "headline": enriched_scan["headline"],
            "summary": enriched_scan["summary"],
            "risk_score": enriched_scan["risk_score"],
            "severity": enriched_scan["severity"],
            "recommendation": enriched_scan["recommendation"],
            "target": enriched_scan["target"],
            "findings_preview": [enrich_finding(finding) for finding in findings[:10]],
        }

    @app.get("/v1/rules", response_model=RuleListResponse)
    async def list_rules() -> RuleListResponse:
        """Return rule metadata for documentation and frontend filters."""
        return RuleListResponse(items=[RuleDocResponse(**item) for item in all_rule_docs()])

    @app.get("/v1/rules/{rule_id}", response_model=RuleDocResponse)
    async def get_rule(rule_id: str) -> RuleDocResponse:
        """Return one rule documentation entry."""
        return RuleDocResponse(**get_rule_doc(rule_id.upper()))

    return app


api_config = load_api_config()
app = create_app(api_config)


def run() -> None:
    """Run the API with uvicorn."""
    import uvicorn

    uvicorn.run(
        "skillspector.api.main:app",
        host=api_config.host,
        port=api_config.port,
        reload=False,
    )
