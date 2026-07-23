"""Background worker for queued deterministic scan jobs."""

from __future__ import annotations

import asyncio
from typing import Any

from skillspector.logging_config import get_logger

from .byok import agent_review_secret_vault
from .config import load_api_config
from .guardrails import cleanup_stale_workdirs
from .scanner import run_deterministic_scan
from .store import ApiStore

logger = get_logger(__name__)


async def process_next_scan_once(store: ApiStore, *, timeout_seconds: float | None = None) -> bool:
    """Claim and process the next queued scan, returning True when work was done."""
    scan = store.claim_next_scan()
    if scan is None:
        return False

    scan_id = scan["scan_id"]
    scan_kwargs: dict[str, Any] = {}
    agent_review_secret = agent_review_secret_vault.pop(scan_id)
    if bool(scan.get("agent_review_requested")):
        scan_kwargs["agent_review_enabled"] = True
    if scan.get("agent_review_provider"):
        scan_kwargs["agent_review_provider"] = scan.get("agent_review_provider")
    if scan.get("agent_review_skill"):
        scan_kwargs["agent_review_skill"] = scan.get("agent_review_skill")
    if scan.get("agent_review_prompt"):
        scan_kwargs["agent_review_prompt"] = scan.get("agent_review_prompt")
    if scan.get("agent_review_model"):
        scan_kwargs["agent_review_model"] = scan.get("agent_review_model")
    if agent_review_secret is not None:
        scan_kwargs["agent_review_api_key"] = agent_review_secret.api_key

    try:
        summary, reports, findings = await asyncio.wait_for(
            run_deterministic_scan(
                scan["target"],
                scan["requested_formats"],
                **scan_kwargs,
            ),
            timeout=timeout_seconds,
        )
        store.complete_scan(scan_id, summary=summary, reports=reports, findings=findings)
        logger.info("Completed deterministic scan %s for %s", scan_id, scan["target"])
    except TimeoutError:
        store.fail_scan(scan_id, f"scan exceeded timeout of {timeout_seconds} seconds")
        logger.exception("Deterministic scan %s timed out", scan_id)
    except Exception as exc:
        store.fail_scan(scan_id, str(exc))
        logger.exception("Deterministic scan %s failed", scan_id)
    finally:
        agent_review_secret_vault.delete(scan_id)
    return True


def run() -> None:
    """Run the worker loop forever."""
    config = load_api_config()
    store = ApiStore(config.db_path)
    store.init_db()
    removed = cleanup_stale_workdirs(
        config.work_dir,
        max_age_seconds=config.max_temp_dir_age_seconds,
    )
    logger.info("Worker started with db=%s", config.db_path)
    if removed:
        logger.info("Removed %d stale temp work directories from %s", removed, config.work_dir)

    while True:
        processed = asyncio.run(
            process_next_scan_once(store, timeout_seconds=config.max_scan_timeout_seconds)
        )
        if not processed:
            asyncio.run(asyncio.sleep(config.worker_poll_seconds))
