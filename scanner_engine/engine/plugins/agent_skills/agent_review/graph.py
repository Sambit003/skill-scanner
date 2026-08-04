"""Bounded LangGraph agent review for deterministic findings."""

from __future__ import annotations

import json
from importlib import resources
from textwrap import dedent
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field

from scanner_engine.engine.plugins.agent_skills.presentation import get_rule_doc
from scanner_engine.engine.plugins.agent_skills.llm_utils import AgentCLIChatModel, get_chat_model
from scanner_engine.engine.plugins.agent_skills.models import Finding
from scanner_engine.engine.plugins.agent_skills.providers import reset_provider, use_provider
from scanner_engine.engine.plugins.agent_skills.providers.chat_models import create_openai_compatible_chat_model

MAX_AGENT_STEPS = 6
DEFAULT_REVIEW_SKILL = "deterministic_triage"
DEFAULT_SUMMARY_SKILL = "executive_summary"
DEFAULT_OPENROUTER_MODEL = "~openai/gpt-latest"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class ReviewedFinding(BaseModel):
    """One finding-level agent judgment."""

    finding_key: str = Field(description="Stable rule/file/line identifier.")
    disposition: Literal["keep", "likely_false_positive", "likely_duplicate", "needs_human_review"]
    rationale: str = Field(description="Evidence-based explanation grounded in deterministic output.")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0.")


class AgentReviewReport(BaseModel):
    """Structured result returned by the bounded reviewer."""

    overall_verdict: Literal["confirm_safe", "confirm_unsafe", "mixed_signal", "needs_human_review", "cautionary"]
    executive_summary: str = Field(description="Short analyst-style summary for the frontend.")
    top_confirmed_risks: list[str] = Field(default_factory=list)
    likely_false_positives: list[ReviewedFinding] = Field(default_factory=list)
    likely_duplicates: list[ReviewedFinding] = Field(default_factory=list)
    follow_up_actions: list[str] = Field(default_factory=list)
    review_confidence: float = Field(description="Confidence score from 0.0 to 1.0.")


class AgentReviewState(MessagesState, total=False):
    """Internal state for the review subgraph."""

    deterministic_summary: dict[str, Any]
    findings: list[dict[str, Any]]
    file_cache: dict[str, str]
    manifest: dict[str, object]
    review_skill_name: str
    review_prompt: str | None
    review_provider: str | None
    review_model: str | None
    review_api_key: str | None
    steps_taken: int
    final_report: dict[str, Any] | None


class AdHocOpenRouterProvider:
    """Minimal injected provider for per-scan OpenRouter BYOK review."""

    DEFAULT_MODEL = DEFAULT_OPENROUTER_MODEL
    SLOT_DEFAULTS: dict[str, str] = {}

    def __init__(self, *, api_key: str, model: str) -> None:
        self._api_key = api_key
        self._model = model or self.DEFAULT_MODEL

    def resolve_credentials(self) -> tuple[str, str | None] | None:
        return self._api_key, OPENROUTER_BASE_URL

    def create_chat_model(
        self,
        model: str,
        *,
        max_tokens: int,
        timeout: float | None = 120,
    ) -> BaseChatModel | None:
        return create_openai_compatible_chat_model(
            model=model,
            credentials=self.resolve_credentials(),
            max_tokens=max_tokens,
            timeout=timeout,
            default_headers={"X-Title": "SkillSpector"},
        )

    def get_context_length(self, model: str) -> int | None:
        return None

    def get_max_output_tokens(self, model: str) -> int | None:
        return None

    def resolve_model(self, slot: str = "default") -> str:
        return self._model


def _get_review_model(review_state: AgentReviewState) -> BaseChatModel | AgentCLIChatModel:
    """Resolve the model for bounded review, including ad-hoc OpenRouter BYOK."""
    review_provider = str(review_state.get("review_provider") or "").strip().lower()
    review_model = str(review_state.get("review_model") or DEFAULT_OPENROUTER_MODEL)
    if review_provider == "openrouter":
        review_api_key = str(review_state.get("review_api_key") or "").strip()
        if not review_api_key:
            raise ValueError("OpenRouter API key missing for bounded agent review.")
        token = use_provider(
            AdHocOpenRouterProvider(
                api_key=review_api_key,
                model=review_model,
            )
        )
        try:
            return get_chat_model(model=review_model)
        finally:
            reset_provider(token)

    return get_chat_model(model=review_state.get("review_model"))


def _skill_text(skill_name: str) -> str:
    """Load one packaged review skill prompt."""
    try:
        return resources.files("skillspector.agent_review.skills").joinpath(
            f"{skill_name}.md"
        ).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"unknown agent review skill: {skill_name}") from exc


def _finding_key(finding: dict[str, Any]) -> str:
    """Build a stable key for one deterministic finding."""
    location = finding.get("location") or {}
    return (
        f"{finding.get('id', 'UNKNOWN')}|"
        f"{location.get('file', 'SKILL.md')}|"
        f"{location.get('start_line', 1)}"
    )


def _deterministic_summary_payload(state: dict[str, Any]) -> dict[str, Any]:
    """Project main graph state to a compact deterministic summary."""
    return {
        "risk_score": state.get("risk_score"),
        "risk_severity": state.get("risk_severity"),
        "risk_recommendation": state.get("risk_recommendation"),
        "manifest": state.get("manifest") or {},
        "findings_count": len(state.get("filtered_findings") or state.get("findings") or []),
    }


def _normalized_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings as plain dicts for review tools."""
    findings: list[Finding] = state.get("filtered_findings") or state.get("findings") or []
    return [finding.to_dict() if isinstance(finding, Finding) else finding for finding in findings]


def _build_tools(review_state: AgentReviewState) -> list[Any]:
    """Create bounded review tools over one scan's deterministic evidence."""
    findings = review_state["findings"]
    findings_by_key = {_finding_key(finding): finding for finding in findings}
    file_cache = review_state.get("file_cache") or {}
    summary = review_state["deterministic_summary"]

    @tool
    def load_skill(skill_name: str) -> str:
        """Load a specialized review skill prompt by name."""
        return _skill_text(skill_name)

    @tool
    def get_scan_summary() -> str:
        """Return the deterministic scan summary and high-level counts."""
        return json.dumps(summary, ensure_ascii=False, indent=2)

    @tool
    def list_findings(severity: str = "ALL", limit: int = 20) -> str:
        """List deterministic findings, optionally filtered by severity."""
        normalized_severity = severity.upper().strip()
        selected = findings
        if normalized_severity and normalized_severity != "ALL":
            selected = [
                finding for finding in findings if str(finding.get("severity") or "").upper() == normalized_severity
            ]
        rows = [
            {
                "finding_key": _finding_key(finding),
                "rule_id": finding.get("id"),
                "severity": finding.get("severity"),
                "category": finding.get("category"),
                "pattern": finding.get("pattern"),
                "location": finding.get("location"),
            }
            for finding in selected[: max(1, min(limit, 50))]
        ]
        return json.dumps(rows, ensure_ascii=False, indent=2)

    @tool
    def get_finding(finding_key: str) -> str:
        """Return the full deterministic payload for one finding key."""
        finding = findings_by_key.get(finding_key)
        if finding is None:
            return json.dumps({"error": "finding not found", "finding_key": finding_key}, ensure_ascii=False)
        return json.dumps(finding, ensure_ascii=False, indent=2)

    @tool
    def get_file_snippet(path: str, start_line: int, end_line: int | None = None, context_lines: int = 8) -> str:
        """Return a bounded source snippet from the deterministic scan cache."""
        content = file_cache.get(path)
        if content is None:
            return json.dumps({"error": "file not available", "path": path}, ensure_ascii=False)
        lines = content.splitlines()
        start_index = max(0, int(start_line) - 1 - max(0, context_lines))
        target_end = int(end_line or start_line)
        end_index = min(len(lines), target_end + max(0, context_lines))
        snippet = "\n".join(lines[start_index:end_index])
        return json.dumps(
            {
                "path": path,
                "start_line": start_index + 1,
                "end_line": end_index,
                "snippet": snippet,
            },
            ensure_ascii=False,
            indent=2,
        )

    @tool
    def get_rule_documentation(rule_id: str) -> str:
        """Return remediation and category details for a deterministic rule id."""
        return json.dumps(get_rule_doc(rule_id.upper()), ensure_ascii=False, indent=2)

    return [
        load_skill,
        get_scan_summary,
        list_findings,
        get_finding,
        get_file_snippet,
        get_rule_documentation,
    ]


def _review_system_prompt(review_state: AgentReviewState) -> str:
    """Build the reviewer system prompt using context-engineering constraints."""
    return dedent(
        f"""
        You are SkillSpector's bounded review agent.

        Your job is to review deterministic findings without changing the deterministic scan itself.

        Rules:
        - The deterministic findings are the primary evidence.
        - Never invent repository facts.
        - Use tools before claiming a finding is a false positive or duplicate.
        - Be especially careful with:
          - documentation examples versus executable code
          - normal cloud/API authentication flows versus exfiltration
          - duplicated paths or mirrored plugin layouts
        - Do not claim a repository is malware unless the evidence is explicit.
        - Keep the review focused on triage quality, not broad code refactoring.
        - If evidence is mixed or incomplete, prefer `needs_human_review`.
        - Before analyzing, call `load_skill` for `{review_state['review_skill_name']}`.
        """
    ).strip()


def _review_user_prompt(review_state: AgentReviewState) -> str:
    """Build the reviewer task message."""
    manifest = review_state.get("manifest") or {}
    custom_prompt = (review_state.get("review_prompt") or "").strip()
    return dedent(
        f"""
        Review this deterministic scan and prepare an evidence-backed triage.

        Repository metadata:
        {json.dumps(manifest, ensure_ascii=False, indent=2)}

        Deterministic summary:
        {json.dumps(review_state['deterministic_summary'], ensure_ascii=False, indent=2)}

        There are {len(review_state['findings'])} deterministic findings available via tools.

        Goals:
        1. Confirm the highest-signal risks.
        2. Identify likely false positives with evidence.
        3. Identify likely duplicates with evidence.
        4. Produce a concise executive summary for the UI.

        {custom_prompt if custom_prompt else "No custom analyst prompt was provided."}
        """
    ).strip()


def _route_after_reviewer(state: AgentReviewState) -> str:
    """Route to tools while the model is still calling them, then finalize."""
    messages = state.get("messages") or []
    if not messages:
        return "finalize"
    last_message = messages[-1]
    if isinstance(last_message, AIMessage) and getattr(last_message, "tool_calls", None):
        if int(state.get("steps_taken") or 0) < MAX_AGENT_STEPS:
            return "tools"
    return "finalize"


def _reviewer_node(review_state: AgentReviewState) -> dict[str, Any]:
    """Run one bounded tool-calling reasoning step."""
    model = _get_review_model(review_state)
    if not hasattr(model, "bind_tools"):
        raise ValueError(
            "Configured LLM provider does not support tool binding for agent review. "
            "Use an HTTP-backed provider such as OpenAI, Anthropic, or nv_build."
        )

    tools = _build_tools(review_state)
    bound_model = model.bind_tools(tools)  # type: ignore[attr-defined]
    response = bound_model.invoke(review_state["messages"])
    return {"messages": [response], "steps_taken": int(review_state.get("steps_taken") or 0) + 1}


def _finalize_node(review_state: AgentReviewState) -> dict[str, Any]:
    """Convert the gathered evidence into a structured review report."""
    model = _get_review_model(review_state)
    summary_skill = _skill_text(DEFAULT_SUMMARY_SKILL)
    transcript = []
    for message in review_state.get("messages") or []:
        role = getattr(message, "type", message.__class__.__name__)
        content = getattr(message, "content", "")
        transcript.append(f"{role}: {content}")

    prompt = dedent(
        f"""
        You are finalizing a deterministic scan review for SkillSpector.

        Use the deterministic summary, the evidence gathered via tools, and the reviewer transcript below.
        Do not invent facts outside this transcript.

        Summary skill:
        {summary_skill}

        Deterministic summary:
        {json.dumps(review_state['deterministic_summary'], ensure_ascii=False, indent=2)}

        Reviewer transcript:
        {"\n\n".join(transcript[-12:])}
        """
    ).strip()

    structured_model = model.with_structured_output(AgentReviewReport)
    final_report = structured_model.invoke(prompt)
    return {"final_report": final_report.model_dump(mode="json")}


def _build_review_graph(review_state: AgentReviewState):
    """Build one bounded review subgraph."""
    workflow = StateGraph(AgentReviewState)
    workflow.add_node("reviewer", _reviewer_node)
    workflow.add_node("tools", ToolNode(_build_tools(review_state)))
    workflow.add_node("finalize", _finalize_node)
    workflow.add_edge(START, "reviewer")
    workflow.add_conditional_edges(
        "reviewer",
        _route_after_reviewer,
        {"tools": "tools", "finalize": "finalize"},
    )
    workflow.add_edge("tools", "reviewer")
    workflow.add_edge("finalize", END)
    return workflow.compile()


def _normalize_report(state: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic sanity guards to the structured agent-review output."""
    findings_count = int(state.get("findings_count") or 0)
    risk_score = int(state.get("risk_score") or 0)
    if findings_count == 0 and risk_score == 0:
        report["overall_verdict"] = "confirm_safe"
    return report


def run_agent_review(state: dict[str, Any]) -> dict[str, Any]:
    """Run the optional bounded agent review over deterministic findings."""
    if not state.get("agent_review_enabled"):
        return {
            "agent_review_requested": False,
            "agent_review_used": False,
            "agent_review_status": "skipped",
            "agent_review_report": None,
            "agent_review_summary": None,
            "agent_review_verdict": None,
        }

    review_state: AgentReviewState = {
        "messages": [
            SystemMessage(content=_review_system_prompt(
                {
                    "review_skill_name": str(state.get("agent_review_skill") or DEFAULT_REVIEW_SKILL),
                    "review_prompt": state.get("agent_review_prompt"),
                }
            )),
            HumanMessage(
                content=_review_user_prompt(
                    {
                        "deterministic_summary": _deterministic_summary_payload(state),
                        "findings": _normalized_findings(state),
                        "manifest": state.get("manifest") or {},
                        "review_prompt": state.get("agent_review_prompt"),
                    }
                )
            ),
        ],
        "deterministic_summary": _deterministic_summary_payload(state),
        "findings": _normalized_findings(state),
        "file_cache": state.get("file_cache") or {},
        "manifest": state.get("manifest") or {},
        "review_skill_name": str(state.get("agent_review_skill") or DEFAULT_REVIEW_SKILL),
        "review_prompt": state.get("agent_review_prompt"),
        "review_provider": state.get("agent_review_provider"),
        "review_model": state.get("agent_review_model"),
        "review_api_key": state.get("agent_review_api_key"),
        "steps_taken": 0,
    }

    try:
        result = _build_review_graph(review_state).invoke(review_state)
    except Exception as exc:
        return {
            "agent_review_requested": True,
            "agent_review_used": False,
            "agent_review_status": "failed",
            "agent_review_report": None,
            "agent_review_summary": str(exc),
            "agent_review_verdict": None,
        }

    report = result.get("final_report")
    if not isinstance(report, dict):
        return {
            "agent_review_requested": True,
            "agent_review_used": False,
            "agent_review_status": "failed",
            "agent_review_report": None,
            "agent_review_summary": "agent review returned no structured report",
            "agent_review_verdict": None,
        }

    report = _normalize_report(state, report)
    return {
        "agent_review_requested": True,
        "agent_review_provider": state.get("agent_review_provider"),
        "agent_review_used": True,
        "agent_review_status": "completed",
        "agent_review_report": report,
        "agent_review_summary": report.get("executive_summary"),
        "agent_review_verdict": report.get("overall_verdict"),
    }
