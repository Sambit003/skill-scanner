import asyncio
import concurrent.futures
import logging
from backend.core.celery_app import celery_app
from backend.core.database import WorkerAsyncSessionLocal
from backend.repositories.scan_repository import ScanRepository
from backend.services.scanner_client import ScannerClient

logger = logging.getLogger(__name__)

async def _execute_scan_pipeline(
    scan_id: str,
    target: str,
    asset_type: str,
    scan_scope: str,
    include_readme: bool,
) -> None:
    """Async execution of the deterministic scan state machine."""
    async with WorkerAsyncSessionLocal() as session:
        repo = ScanRepository(session)
        try:
            # 1. State: FETCHING (validating & preparing target)
            logger.info(f"[{scan_id}] Stage 1: FETCHING target {target}")
            await repo.update_stage(scan_id, "FETCHING", status="IN_PROGRESS")

            # 2. State: DETER_SCAN (AST, YARA, Behavioral scanning)
            logger.info(f"[{scan_id}] Stage 2: DETER_SCAN")
            await repo.update_stage(scan_id, "DETER_SCAN")

            scan_result = await ScannerClient().scan(
                target=target,
                asset_type=asset_type,
                scan_scope=scan_scope,
                include_readme=include_readme,
                output_formats=["json", "sarif", "markdown", "terminal"],
            )

            # 4. State: COMPLETED (persisting results)
            logger.info(f"[{scan_id}] Stage 4: COMPLETED with {scan_result.summary.findings_count} findings")
            reports_map = {
                report_format: report.content
                for report_format, report in scan_result.reports.items()
            }
            summary_map = scan_result.summary.model_dump()
            await repo.save_scan_success(
                scan_id=scan_id,
                summary_dict=summary_map,
                findings_list=scan_result.findings,
                reports_dict=reports_map,
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
    scan_scope: str = "skill_folders",
    include_readme: bool = False,
) -> None:
    """Celery task entrypoint."""
    _run_coroutine_sync(
        _execute_scan_pipeline(
            scan_id=scan_id,
            target=target,
            asset_type=asset_type,
            scan_scope=scan_scope,
            include_readme=include_readme,
        )
    )
