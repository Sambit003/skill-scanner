from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.api.v1.router import api_v1_router
from backend.core.config import settings
from backend.core.database import engine, Base
from backend.domain.repository_identity import repository_key as normalize_repository_key

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables on startup if they do not exist
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # Existing Compose deployments retain PostgreSQL volumes. Keep this
            # additive migration idempotent so those scan records remain usable.
            await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_scope VARCHAR(32)"))
            await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS include_readme BOOLEAN"))
            await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS repository_key VARCHAR(512)"))
            # Nullable: scans recorded before capabilities existed keep NULL.
            await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS capabilities JSON"))
            await conn.execute(text("UPDATE scans SET scan_scope = 'repository' WHERE scan_scope IS NULL"))
            await conn.execute(text("UPDATE scans SET include_readme = TRUE WHERE include_readme IS NULL"))
            await conn.execute(text("ALTER TABLE scans ALTER COLUMN scan_scope SET DEFAULT 'skill_folders'"))
            await conn.execute(text("ALTER TABLE scans ALTER COLUMN scan_scope SET NOT NULL"))
            await conn.execute(text("ALTER TABLE scans ALTER COLUMN include_readme SET DEFAULT FALSE"))
            await conn.execute(text("ALTER TABLE scans ALTER COLUMN include_readme SET NOT NULL"))
            legacy_scans = await conn.execute(text("SELECT id, asset_target FROM scans WHERE repository_key IS NULL"))
            for scan in legacy_scans.mappings():
                await conn.execute(
                    text("UPDATE scans SET repository_key = :repository_key WHERE id = :scan_id"),
                    {"repository_key": normalize_repository_key(scan["asset_target"]), "scan_id": scan["id"]},
                )
            await conn.execute(text("ALTER TABLE scans ALTER COLUMN repository_key SET NOT NULL"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_scan_scope ON scans (scan_scope)"))
            await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_repository_key ON scans (repository_key)"))
        logger.info("Database schema initialized successfully.")
    except Exception as exc:
        logger.warning(f"Database schema initialization warning: {exc}")
    yield
    # Clean up resources on shutdown
    await engine.dispose()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Support both /api/v1 and /v1 prefixes for backward and forward compatibility
app.include_router(api_v1_router, prefix=settings.API_V1_STR)
app.include_router(api_v1_router, prefix="/v1")

@app.get("/")
async def root():
    return {"message": "AIRiskDB Backend API is running.", "docs": f"{settings.API_V1_STR}/docs"}
