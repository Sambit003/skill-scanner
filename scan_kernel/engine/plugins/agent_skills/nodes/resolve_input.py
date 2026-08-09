"""Resolve-input node: normalizes input_path or skill_path to a local directory (skill_path).

Runs as the first graph node. When input_path is a URL, zip, or single file,
resolves to a temp directory and sets temp_dir_for_cleanup so the caller (CLI/API)
can clean up after the graph completes.
"""

from __future__ import annotations

from pathlib import Path

from scan_kernel.engine.plugins.agent_skills.input_handler import InputHandler
from scan_kernel.engine.plugins.agent_skills.logging_config import get_logger
from scan_kernel.engine.plugins.agent_skills.state import ScanKernelState

logger = get_logger(__name__)


def resolve_input(state: ScanKernelState) -> dict[str, object]:
    """
    Resolve input to a scannable directory.

    - If state has non-empty input_path: resolve it (Git URL, file URL, zip, file, or directory)
      and set skill_path. If resolution created a temp dir, set temp_dir_for_cleanup.
    - Else if state has skill_path: normalize to absolute path and set skill_path.
    - Else: set skill_path to None (build_context will raise a user-facing error).
    """
    input_path = state.get("input_path")
    skill_path = state.get("skill_path")

    if input_path and isinstance(input_path, str) and input_path.strip():
        handler = InputHandler()
        try:
            resolved, source_type = handler.resolve(input_path.strip())
            update: dict[str, object] = {"skill_path": str(resolved)}
            temp_dir = handler.temp_dir_for_cleanup()
            if temp_dir is not None:
                update["temp_dir_for_cleanup"] = str(temp_dir)
            else:
                update["temp_dir_for_cleanup"] = None
            return update
        except (ValueError, FileNotFoundError):
            raise

    if skill_path and isinstance(skill_path, str) and skill_path.strip():
        try:
            resolved = Path(skill_path).resolve()
            return {
                "skill_path": str(resolved),
                "temp_dir_for_cleanup": None,
            }
        except (OSError, RuntimeError) as e:
            logger.warning("Could not resolve skill_path: %s", e)
            return {"skill_path": None, "temp_dir_for_cleanup": None}

    return {"skill_path": None, "temp_dir_for_cleanup": None}
