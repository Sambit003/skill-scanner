# ScanKernel Demo

ScanKernel is a deterministic security scanner for AI skill repositories. The
application accepts a Git URL, local directory, archive, or skill manifest, runs
static analyzers, stores the result, and exposes JSON, Markdown, SARIF, and
terminal reports.

The scan path is local and deterministic. It does not execute scanned code or
send scan content to an external model service.

## Monorepo

- `apps/frontend/`: Next.js dashboard
- `apps/backend/`: FastAPI API and Celery worker
- `packages/scan_kernel/`: current Python scanner engine; the next implementation can replace it with Go
- `contracts/scan-kernel/v1/`: language-neutral scanner process contract

[moon](https://moonrepo.dev/) owns the project and task graph. pnpm remains the
JavaScript package manager, uv remains the Python workspace manager, and Go is
already part of the pinned toolchain for the next scanner iteration.

Install [proto](https://moonrepo.dev/proto) once, then provision the repository's
major/minor tool families and dependencies:

```bash
proto install
moon run workspace:setup
```

Authoritative local workflows:

```bash
moon run workspace:check
moon run workspace:dev
moon run frontend:dev
moon run backend:dev
moon run scan-kernel:smoke
```

Moon caches deterministic tasks locally. CI and remote caching are intentionally
not configured in this iteration.

## Run with Docker Compose

```bash
docker compose up --build
```

Then open:

- Frontend: `http://localhost:3000`
- API: `http://localhost:8000`
- Health: `http://localhost:8000/api/v1/health`

Stop the stack with `docker compose down`. The Compose file intentionally does
not manage a Cloudflare Tunnel.

## Scanner process boundary

The worker invokes `scan-kernel-engine`, writes one protocol-v1 JSON request to
stdin, and reads one JSON response from stdout. Findings—including critical
findings—are successful process results. Invalid requests exit `2`; scanner
execution failures exit `3`; diagnostic logs are written to stderr.

Protocol v1 exposes `scan`, `list_rules`, and `get_rule` operations, so the API
does not import scanner implementation modules for either execution or rule
metadata.

The backend depends only on this contract. A future Go binary can replace the
Python launcher at `/usr/local/bin/scan-kernel-engine` without changing the
worker, database, frontend, or HTTP API.

The public API remains mounted at `/api/v1` and `/v1`:

- `POST /v1/scans`
- `GET /v1/scans/{scan_id}`
- `GET /v1/scans/{scan_id}/findings`
- `GET /v1/scans/{scan_id}/reports`
- `GET /v1/scans/{scan_id}/reports/{format}`
- `GET /v1/rules`
- `GET /v1/rules/{rule_id}`
