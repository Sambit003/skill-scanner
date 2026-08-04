from celery import Celery
from backend.core.config import settings

celery_app = Celery(
    "riskdb_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["backend.workers.scan_worker"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour maximum
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
)
