FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN python -m venv .venv
RUN .venv/bin/pip install --no-cache-dir .

FROM python:3.12-slim-bookworm AS runtime-base

RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system skillspector \
    && useradd --system --gid skillspector --create-home --home-dir /home/skillspector skillspector

COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE="1"
ENV PYTHONUNBUFFERED="1"
WORKDIR /scan

FROM runtime-base AS api

ENV SKILLSPECTOR_DATA_DIR="/data"
ENV SKILLSPECTOR_WORK_DIR="/tmp/skillspector-scans"
ENV SKILLSPECTOR_API_HOST="0.0.0.0"
ENV SKILLSPECTOR_API_PORT="8000"
ENV SKILLSPECTOR_CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"

RUN mkdir -p /data /tmp/skillspector-scans /scan \
    && chown -R skillspector:skillspector /data /tmp/skillspector-scans /scan /home/skillspector /app

USER skillspector

EXPOSE 8000

ENTRYPOINT ["skillspector-api"]

FROM runtime-base AS cli

ENTRYPOINT ["skillspector"]
