# ScanKernel Demo

ScanKernel is a deterministic security scanner for AI skill repositories. The application accepts a Git URL, local directory, archive, or skill manifest; runs static analyzers; stores the result; and exposes JSON, Markdown, SARIF, and terminal reports.

The scan path is fully local and deterministic. It does not execute scanned code or send scan content to an external model service.

## Architecture

- `frontend/`: Next.js dashboard for starting scans and reviewing results
- `backend/`: FastAPI API and Celery worker
- `scan_kernel/`: native Python pipeline with pattern, AST, taint, YARA, supply-chain, and MCP analyzers
- PostgreSQL: scan metadata, summaries, findings, and rendered reports
- Redis: Celery broker and result backend

The scanner pipeline runs these stages:

1. Resolve and safely prepare the input.
2. Build the file and manifest context.
3. Run deterministic analyzers.
4. Apply confidence filtering and default remediations.
5. Score, suppress, and render reports.

## Run with Docker Compose

```bash
docker compose up --build
```

Then open:

- Frontend: `http://localhost:3000`
- API: `http://localhost:8000`
- Health: `http://localhost:8000/api/v1/health`

Stop the stack with:

```bash
docker compose down
```

## API

The API is mounted at both `/api/v1` and `/v1`. The browser client uses `NEXT_PUBLIC_API_URL` to reach the backend directly.

- `POST /v1/scans` starts a scan with `{ "target": "...", "asset_type": "agent_skill" }`.
- `GET /v1/scans/{scan_id}` returns status and summary data.
- `GET /v1/scans/{scan_id}/findings` returns filterable findings.
- `GET /v1/scans/{scan_id}/reports` lists report downloads.
- `GET /v1/scans/{scan_id}/reports/{format}` returns `json`, `markdown`, `sarif`, or `terminal` output.
- `GET /v1/rules` and `GET /v1/rules/{rule_id}` expose rule documentation.

## Local validation

```bash
python3 -m compileall -q backend scan_kernel/engine
python3 -m pip check
cd frontend
npm run lint
npm run build
```

For a direct scanner smoke test:

```bash
python3 -m scan_kernel.engine.plugins.agent_skills.cli scan . --format json
```

## Deployment notes

The frontend is the public service and the browser reaches the backend at its configured public URL. The Compose file intentionally does not manage a Cloudflare Tunnel; an externally managed tunnel can target the published frontend port.
