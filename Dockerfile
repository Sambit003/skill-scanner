FROM node:20-bookworm-slim AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
ARG NEXT_PUBLIC_API_URL=/api
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN npm run build

FROM python:3.12-slim-bookworm AS backend-builder

WORKDIR /app/backend
COPY SkillSpector/pyproject.toml SkillSpector/README.md ./
COPY SkillSpector/src/ ./src/
RUN python -m venv .venv
RUN .venv/bin/pip install --no-cache-dir .

FROM node:20-bookworm-slim AS node-runtime

FROM python:3.12-slim-bookworm AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system appgroup \
    && useradd --system --gid appgroup --create-home --home-dir /home/appuser appuser

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=caddy:2.10 /usr/bin/caddy /usr/bin/caddy

WORKDIR /app

COPY --from=backend-builder /app/backend/.venv /app/backend/.venv
COPY --from=frontend-builder /app/frontend/.next/standalone /app/frontend
COPY --from=frontend-builder /app/frontend/.next/static /app/frontend/.next/static
COPY --from=frontend-builder /app/frontend/public /app/frontend/public

COPY deploy/Caddyfile.single /etc/caddy/Caddyfile
COPY deploy/supervisord.single.conf /etc/supervisor/conf.d/supervisord.conf

ENV PATH="/app/backend/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE="1"
ENV PYTHONUNBUFFERED="1"
ENV PORT="3000"
ENV HOSTNAME="127.0.0.1"
ENV SKILLSPECTOR_DATA_DIR="/data"
ENV SKILLSPECTOR_DB_PATH="/data/skillspector.db"
ENV SKILLSPECTOR_WORK_DIR="/tmp/skillspector-scans"
ENV SKILLSPECTOR_API_HOST="127.0.0.1"
ENV SKILLSPECTOR_API_PORT="8000"
ENV SKILLSPECTOR_CORS_ORIGINS="*"
ENV SKILLSPECTOR_EMBEDDED_WORKER_ENABLED="true"

RUN mkdir -p /data /tmp/skillspector-scans /var/log/supervisor /run /home/appuser \
    && chown -R appuser:appgroup /app /data /tmp/skillspector-scans /var/log/supervisor /run /home/appuser

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
