# ==============================================================================
# Stage 1: Build & Dependency Resolution
# ==============================================================================
FROM python:3.12-slim-bookworm AS builder

# Set build environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    git \
    pkg-config \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast, reliable package resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /build

# Create isolated virtual environment in /app/.venv
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    VIRTUAL_ENV="/app/.venv"

# Copy package configurations
COPY scan_kernel/pyproject.toml ./scan_kernel/
COPY backend/pyproject.toml ./backend/

# Install core dependencies into virtualenv
RUN uv pip install --no-cache \
    hatchling \
    "fastapi>=0.111.0" \
    "uvicorn[standard]>=0.30.0" \
    "pydantic>=2.7.0" \
    "pydantic-settings>=2.2.1" \
    "sqlalchemy[asyncio]>=2.0.30" \
    "asyncpg>=0.29.0" \
    "aiosqlite>=0.20.0" \
    "greenlet>=3.0.0" \
    "redis>=5.0.0" \
    "celery>=5.4.0" \
    "httpx>=0.27.0" \
    "pyyaml>=6.0.1" \
    "yara-python>=4.5.0" \
    "typer>=0.12.0" \
    "rich>=13.0.0"

# ==============================================================================
# Stage 2: Minimal Production Runtime
# ==============================================================================
FROM python:3.12-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app"

# Install minimal runtime libraries (curl for healthchecks, git for target fetching)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user and group
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Copy virtualenv from builder stage
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv

# Copy application source code
COPY --chown=appuser:appgroup scan_kernel/ /app/scan_kernel/
COPY --chown=appuser:appgroup backend/ /app/backend/

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default CMD (API Server)
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
