import asyncio
from copy import copy
from typing import Any, Dict, List
from scanner_engine.engine.models import (
    ReportContent,
    ReportFormat,
    ScanConfig,
    ScanResult,
    ScanSummary,
)
from scanner_engine.engine.plugins.base import BaseAssetPlugin
from scanner_engine.engine.plugins.agent_skills.cleanup import cleanup_result
from scanner_engine.engine.plugins.agent_skills.constants import RISK_THRESHOLD
from scanner_engine.engine.plugins.agent_skills.graph import graph
from scanner_engine.engine.plugins.agent_skills.nodes.report import report

CONTENT_TYPES: Dict[ReportFormat, str] = {
    ReportFormat.JSON: "application/json",
    ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ReportFormat.SARIF: "application/sarif+json",
    ReportFormat.TERMINAL: "text/plain; charset=utf-8",
}

class AgentSkillPlugin(BaseAssetPlugin):
    """Plugin for scanning Agent Skills using deterministic AST/YARA analyzers and optional LLM review."""

    @property
    def asset_type(self) -> str:
        return "agent_skill"

    @property
    def supported_extensions(self) -> List[str]:
        return [".py", ".sh", ".md", ".json", ".yaml", ".yml", ".zip"]

    async def scan_async(self, config: ScanConfig) -> ScanResult:
        requested_unique = list(dict.fromkeys(config.output_formats))
        canonical_format = (
            ReportFormat.JSON if ReportFormat.JSON in requested_unique else requested_unique[0]
        )
        formats_to_render = list(dict.fromkeys([*requested_unique, ReportFormat.JSON]))

        initial_state: Dict[str, Any] = {
            "input_path": config.target,
            "output_format": canonical_format.value,
            "use_llm": config.use_llm,
        }

        if config.yara_rules_dir:
            initial_state["yara_rules_dir"] = str(config.yara_rules_dir)

        if config.baseline_path:
            initial_state["baseline_path"] = str(config.baseline_path)

        if config.agent_review and config.agent_review.enabled:
            initial_state.update({
                "agent_review_enabled": True,
                "agent_review_provider": config.agent_review.provider,
                "agent_review_skill": config.agent_review.skill,
                "agent_review_prompt": config.agent_review.prompt,
                "agent_review_model": config.agent_review.model,
                "agent_review_api_key": config.agent_review.api_key,
            })

        run_name = config.run_name or f"scan-agent-skill-{canonical_format.value}"
        tags = config.tags or ["scanner_engine", "agent_skill"]

        result: Dict[str, Any] | None = None
        try:
            coro = graph.ainvoke(
                initial_state,
                config={
                    "run_name": run_name,
                    "tags": tags,
                    "metadata": {
                        "input_path": config.target,
                        "use_llm": config.use_llm,
                        "output_format": canonical_format.value,
                    },
                },
            )

            if config.timeout_seconds:
                result = await asyncio.wait_for(coro, timeout=config.timeout_seconds)
            else:
                result = await coro

            findings = result.get("filtered_findings") or result.get("findings") or []
            normalized_findings = [
                f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings
            ]

            summary = ScanSummary(
                risk_score=int(result.get("risk_score") or 0),
                severity=str(result.get("risk_severity") or "UNKNOWN"),
                recommendation=str(result.get("risk_recommendation") or ""),
                safe_to_install=int(result.get("risk_score") or 0) <= RISK_THRESHOLD,
                findings_count=len(normalized_findings),
                findings_by_severity=self._count_by(normalized_findings, "severity"),
                findings_by_category=self._count_by(normalized_findings, "category"),
                scanner_version="1.0.0",
                scan_mode="static-llm" if config.use_llm else "static-only",
                llm_requested=config.use_llm,
                llm_used=bool(result.get("llm_used")),
                agent_review_requested=bool(config.agent_review and config.agent_review.enabled),
                agent_review_used=bool(result.get("agent_review_used")),
                agent_review_status=result.get("agent_review_status"),
                agent_review_verdict=result.get("agent_review_verdict"),
                agent_review_summary=result.get("agent_review_summary"),
                agent_review_report=result.get("agent_review_report"),
            )

            reports: Dict[ReportFormat, ReportContent] = {}
            for fmt in formats_to_render:
                if fmt == canonical_format:
                    report_body = result.get("report_body") or ""
                else:
                    rendered = report({**copy(result), "output_format": fmt.value, "use_llm": config.use_llm})
                    report_body = rendered.get("report_body") or ""

                reports[fmt] = ReportContent(
                    format=fmt,
                    content=report_body,
                    content_type=CONTENT_TYPES[fmt],
                )

            return ScanResult(
                summary=summary,
                findings=normalized_findings,
                reports=reports,
                raw_graph_state=result,
            )
        finally:
            if result is not None:
                cleanup_result(result)

    def scan_sync(self, config: ScanConfig) -> ScanResult:
        return asyncio.run(self.scan_async(config))

    @staticmethod
    def _count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in items:
            label = str(item.get(key) or "UNKNOWN")
            counts[label] = counts.get(label, 0) + 1
        return counts
