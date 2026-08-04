import asyncio
import concurrent.futures
import logging
from dataclasses import asdict
from typing import Any, Dict, Optional
from backend.core.celery_app import celery_app
from backend.core.database import WorkerAsyncSessionLocal
from backend.repositories.scan_repository import ScanRepository
from scanner_engine.engine import (
    AgentReviewConfig,
    ReportFormat,
    ScanConfig,
    ScanEngine,
)

logger = logging.getLogger(__name__)

async def _execute_scan_pipeline(
    scan_id: str,
    target: str,
    asset_type: str,
    use_llm: bool,
    agent_review_data: Optional[Dict[str, Any]],
) -> None:
    """Async execution of the 5-stage scan state machine."""
    async with WorkerAsyncSessionLocal() as session:
        repo = ScanRepository(session)
        try:
            # 1. State: FETCHING (validating & preparing target)
            logger.info(f"[{scan_id}] Stage 1: FETCHING target {target}")
            await repo.update_stage(scan_id, "FETCHING", status="IN_PROGRESS")

            # Configure agent review DTO
            review_cfg = None
            if agent_review_data and agent_review_data.get("enabled"):
                review_cfg = AgentReviewConfig(
                    enabled=True,
                    provider=agent_review_data.get("provider"),
                    skill=agent_review_data.get("skill"),
                    prompt=agent_review_data.get("prompt"),
                    model=agent_review_data.get("model"),
                    api_key=agent_review_data.get("api_key"),
                )

            # 2. State: DETER_SCAN (AST, YARA, Behavioral scanning)
            logger.info(f"[{scan_id}] Stage 2: DETER_SCAN")
            await repo.update_stage(scan_id, "DETER_SCAN")

            config = ScanConfig(
                target=target,
                asset_type=asset_type,
                use_llm=use_llm,
                agent_review=review_cfg,
                output_formats=[
                    ReportFormat.JSON,
                    ReportFormat.SARIF,
                    ReportFormat.MARKDOWN,
                    ReportFormat.TERMINAL,
                ],
            )

            # 3. State: LLM_ANALYSIS (if enabled)
            if use_llm or (review_cfg and review_cfg.enabled):
                logger.info(f"[{scan_id}] Stage 3: LLM_ANALYSIS")
                await repo.update_stage(scan_id, "LLM_ANALYSIS")

            # Execute Core ScanEngine
            scan_result = await ScanEngine.execute_async(config)

            # 4. State: COMPLETED (persisting results)
            logger.info(f"[{scan_id}] Stage 4: COMPLETED with {scan_result.summary.findings_count} findings")
            reports_map = {
                fmt.value: content.content
                for fmt, content in scan_result.reports.items()
            }
            summary_map = asdict(scan_result.summary)
            agent_review_map = {
                "status": scan_result.summary.agent_review_status,
                "verdict": scan_result.summary.agent_review_verdict,
                "summary": scan_result.summary.agent_review_summary,
                "report": scan_result.summary.agent_review_report,
            }

            await repo.save_scan_success(
                scan_id=scan_id,
                summary_dict=summary_map,
                findings_list=scan_result.findings,
                reports_dict=reports_map,
                agent_review_dict=agent_review_map,
            )

        except Exception as exc:
            logger.exception(f"[{scan_id}] Scan failed: {exc}")
            await repo.save_scan_failure(scan_id, str(exc))

def _run_coroutine_sync(coro):
    """Safely run an async coroutine synchronously across various event loop states."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: asyncio.run(coro))
            return future.result()
    else:
        return asyncio.run(coro)

@celery_app.task(name="backend.workers.scan_worker.run_asset_scan_task", bind=True, max_retries=2)
def run_asset_scan_task(
    self,
    scan_id: str,
    target: str,
    asset_type: str = "agent_skill",
    use_llm: bool = False,
    agent_review_data: Optional[Dict[str, Any]] = None,
) -> None:
    """Celery task entrypoint."""
    _run_coroutine_sync(
        _execute_scan_pipeline(
            scan_id=scan_id,
            target=target,
            asset_type=asset_type,
            use_llm=use_llm,
            agent_review_data=agent_review_data,
        )
    )
