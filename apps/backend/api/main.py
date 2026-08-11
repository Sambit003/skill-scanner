from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.core.config import settings
from backend.core.database import engine, Base
from backend.api.v1.router import api_v1_router
import logging

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables on startup if they do not exist
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
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
