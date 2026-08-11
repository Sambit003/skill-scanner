"""Central logging configuration for the scan_kernel package.

Reads ``SCAN_KERNEL_LOG_LEVEL`` directly from the environment (default
``WARNING``) so this module stays cycle-free — it must be importable from
the providers package, which ``constants`` itself depends on.

Use get_logger(__name__) in modules; use Rich console.print() for user-facing output.
"""

from __future__ import annotations

import logging
import os
import sys

SCAN_KERNEL_LOG_LEVEL = os.environ.get("SCAN_KERNEL_LOG_LEVEL", "WARNING")

_PACKAGE_LOGGER_NAME = "scan_kernel"
_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    root = logging.getLogger(_PACKAGE_LOGGER_NAME)
    root.setLevel(logging.DEBUG)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(_level_from_string(SCAN_KERNEL_LOG_LEVEL))
        handler.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
        root.addHandler(handler)
    root.setLevel(_level_from_string(SCAN_KERNEL_LOG_LEVEL))
    _configured = True


def _level_from_string(level: str) -> int:
    return getattr(logging, level.upper(), logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the scan_kernel package namespace."""
    _configure()
    if name.startswith(_PACKAGE_LOGGER_NAME + ".") or name == _PACKAGE_LOGGER_NAME:
        return logging.getLogger(name)
    return logging.getLogger(f"{_PACKAGE_LOGGER_NAME}.{name}")


def set_level(level: int | str) -> None:
    """Set the package root logger and its handler level (e.g. for CLI --verbose)."""
    _configure()
    lvl = level if isinstance(level, int) else _level_from_string(level)
    root = logging.getLogger(_PACKAGE_LOGGER_NAME)
    root.setLevel(lvl)
    for h in root.handlers:
        h.setLevel(lvl)
