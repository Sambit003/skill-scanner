"""Runtime configuration for the SkillSpector API service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ApiConfig:
    """Environment-backed settings for the API runtime."""

    host: str = "0.0.0.0"
    port: int = 8000
    data_dir: str = "/data"
    work_dir: str = "/tmp/skillspector-scans"
    db_path: str = "/data/skillspector.db"
    worker_poll_seconds: float = 2.0
    cors_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000")
    default_poll_after_ms: int = 2000
    max_scan_timeout_seconds: float = 300.0
    max_target_length: int = 2048
    max_temp_dir_age_seconds: int = 3600
    embedded_worker_enabled: bool = True

    def ensure_directories(self) -> None:
        """Ensure runtime directories exist before the API or worker starts."""
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.work_dir).mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)


def load_api_config() -> ApiConfig:
    """Load API settings from environment variables."""
    port_raw = os.environ.get("SKILLSPECTOR_API_PORT", "8000").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 8000

    poll_raw = os.environ.get("SKILLSPECTOR_WORKER_POLL_SECONDS", "2.0").strip()
    try:
        worker_poll_seconds = float(poll_raw)
    except ValueError:
        worker_poll_seconds = 2.0

    timeout_raw = os.environ.get("SKILLSPECTOR_MAX_SCAN_TIMEOUT_SECONDS", "300").strip()
    try:
        max_scan_timeout_seconds = float(timeout_raw)
    except ValueError:
        max_scan_timeout_seconds = 300.0

    target_length_raw = os.environ.get("SKILLSPECTOR_MAX_TARGET_LENGTH", "2048").strip()
    try:
        max_target_length = int(target_length_raw)
    except ValueError:
        max_target_length = 2048

    poll_after_raw = os.environ.get("SKILLSPECTOR_DEFAULT_POLL_AFTER_MS", "2000").strip()
    try:
        default_poll_after_ms = int(poll_after_raw)
    except ValueError:
        default_poll_after_ms = 2000

    temp_age_raw = os.environ.get("SKILLSPECTOR_MAX_TEMP_DIR_AGE_SECONDS", "3600").strip()
    try:
        max_temp_dir_age_seconds = int(temp_age_raw)
    except ValueError:
        max_temp_dir_age_seconds = 3600
    embedded_worker_raw = os.environ.get("SKILLSPECTOR_EMBEDDED_WORKER_ENABLED", "true").strip()
    embedded_worker_enabled = embedded_worker_raw.lower() not in {"0", "false", "no", "off"}

    data_dir = os.environ.get("SKILLSPECTOR_DATA_DIR", "/data").strip() or "/data"
    work_dir = (
        os.environ.get("SKILLSPECTOR_WORK_DIR", "/tmp/skillspector-scans").strip()
        or "/tmp/skillspector-scans"
    )
    db_path = os.environ.get("SKILLSPECTOR_DB_PATH", "").strip() or str(
        Path(data_dir) / "skillspector.db"
    )
    cors_origins_raw = os.environ.get(
        "SKILLSPECTOR_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).strip()
    cors_origins = tuple(
        origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()
    ) or ("http://localhost:3000",)

    config = ApiConfig(
        host=os.environ.get("SKILLSPECTOR_API_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=port,
        data_dir=data_dir,
        work_dir=work_dir,
        db_path=db_path,
        worker_poll_seconds=worker_poll_seconds,
        cors_origins=cors_origins,
        default_poll_after_ms=default_poll_after_ms,
        max_scan_timeout_seconds=max_scan_timeout_seconds,
        max_target_length=max_target_length,
        max_temp_dir_age_seconds=max_temp_dir_age_seconds,
        embedded_worker_enabled=embedded_worker_enabled,
    )
    config.ensure_directories()
    return config
