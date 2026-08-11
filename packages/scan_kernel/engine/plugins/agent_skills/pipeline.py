"""Native deterministic scanner orchestration."""

from __future__ import annotations

import asyncio
from typing import Any

from scan_kernel.engine.plugins.agent_skills.nodes.analyzers import ANALYZER_NODES
from scan_kernel.engine.plugins.agent_skills.nodes.build_context import build_context
from scan_kernel.engine.plugins.agent_skills.nodes.filter_findings import filter_findings
from scan_kernel.engine.plugins.agent_skills.nodes.report import report
from scan_kernel.engine.plugins.agent_skills.nodes.resolve_input import resolve_input


def run_pipeline(initial_state: dict[str, Any]) -> dict[str, Any]:
    """Run the deterministic scan stages and return their accumulated state."""
    state = dict(initial_state)
    state.update(resolve_input(state))
    state.update(build_context(state))

    findings = list(state.get("findings") or [])
    for analyzer in ANALYZER_NODES.values():
        update = analyzer(state)
        findings.extend(update.get("findings") or [])
    state["findings"] = findings

    state.update(filter_findings(state))
    state.update(report(state))
    return state


async def run_pipeline_async(initial_state: dict[str, Any]) -> dict[str, Any]:
    """Run the synchronous analyzer pipeline without blocking the event loop."""
    return await asyncio.to_thread(run_pipeline, initial_state)
