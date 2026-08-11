"""MCP server exposing ScanKernel scanning as an agent-callable tool.

This lets any MCP-capable agent (Claude Code, Codex CLI, Gemini CLI) or remote
runtime call ``scan_skill`` and gate skill/MCP installs on the verdict, turning
ScanKernel from an out-of-band audit tool into a runtime guardrail.

The scan core (:func:`run_scan`) is deliberately independent of the ``mcp`` SDK
so it can be unit-tested without the optional dependency; :func:`build_server`
wraps it in a FastMCP tool and is only reachable once ``scan_kernel[mcp]`` is
installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scan_kernel.engine.plugins.agent_skills import __version__
from scan_kernel.engine.plugins.agent_skills.cleanup import cleanup_result
from scan_kernel.engine.plugins.agent_skills.constants import RISK_THRESHOLD
from scan_kernel.engine.plugins.agent_skills.logging_config import get_logger
from scan_kernel.engine.plugins.agent_skills.pipeline import run_pipeline_async

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

logger = get_logger(__name__)

VALID_FORMATS = ("json", "markdown", "sarif", "terminal")


async def run_scan(
    target: str,
    *,
    output_format: str = "json",
    yara_rules_dir: str | None = None,
) -> dict[str, Any]:
    """Run ScanKernel and return a structured verdict.

    Args:
        target: Git URL, file URL, ``.zip``, ``.md`` file, or local directory.
        output_format: Format of the embedded ``report`` string. One of
            :data:`VALID_FORMATS`.
        yara_rules_dir: Optional directory of additional YARA rules.

    Returns:
        A JSON-serialisable verdict with ``risk_score`` (0-100), ``severity``,
        ``recommendation``, ``safe_to_install``, ``findings``, the rendered
        ``report``, and the deterministic scan mode.
    """
    if output_format not in VALID_FORMATS:
        raise ValueError(f"output_format must be one of {VALID_FORMATS}, got {output_format!r}")

    state: dict[str, Any] = {
        "input_path": target,
        "output_format": output_format,
    }
    if yara_rules_dir:
        state["yara_rules_dir"] = yara_rules_dir

    logger.debug(
        "MCP scan started: target=%s, format=%s",
        target,
        output_format,
    )

    result: dict[str, Any] | None = None
    try:
        result = await run_pipeline_async(state)
        findings = result.get("filtered_findings") or result.get("findings") or []
        risk_score = int(result.get("risk_score") or 0)
        return {
            "target": target,
            "risk_score": risk_score,
            "severity": result.get("risk_severity"),
            "recommendation": result.get("risk_recommendation"),
            "safe_to_install": risk_score <= RISK_THRESHOLD,
            "findings": [f.to_dict() for f in findings],
            "report": result.get("report_body") or "",
            "scan_mode": "deterministic",
            "version": __version__,
        }
    finally:
        if result is not None:
            cleanup_result(result)


def build_server(name: str = "scan_kernel") -> FastMCP:
    """Construct the FastMCP server exposing the ``scan_skill`` tool.

    Requires the optional ``mcp`` dependency (``pip install 'scan_kernel[mcp]'``).
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "The MCP server requires the optional 'mcp' dependency. "
            "Install it with: pip install 'scan_kernel[mcp]'"
        ) from exc

    server = FastMCP(name)

    @server.tool()
    async def scan_skill(
        target: str,
        output_format: str = "json",
    ) -> dict[str, Any]:
        """Scan an AI agent skill for security risks before installing it.

        Use this before installing or loading any skill or MCP server to decide
        whether it is safe. ``target`` accepts a Git URL, file URL, ``.zip``,
        ``.md`` file, or local directory.

        Returns a verdict with ``risk_score`` (0-100), ``severity``,
        ``recommendation``, ``safe_to_install``, and ``findings``. The
        ``scan_mode`` identifies the deterministic analysis path.
        """
        return await run_scan(target, output_format=output_format)

    return server


def run(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the MCP server over ``stdio`` (local agents) or ``http`` (remote/A2A)."""
    server = build_server()
    if transport == "stdio":
        server.run(transport="stdio")
    elif transport == "http":
        server.settings.host = host
        server.settings.port = port
        server.run(transport="streamable-http")
    else:
        raise ValueError(f"transport must be 'stdio' or 'http', got {transport!r}")
