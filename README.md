# SuperAlign Skill Scanner

Monorepo for the SuperAlign Skill Scanner MVP.

This is a founder-demo / internal-use product for scanning AI skills and skill repositories before review or installation.

The current product is:

- deterministic first
- optional bounded agent review second
- frontend + backend deployable on one VPS in one container
- not intended yet as a hardened public multi-tenant SaaS

## What this product does

The system scans a repo, local path, or skill file and produces:

- normalized security findings
- severity and recommendation
- category and severity breakdowns
- risk score
- downloadable reports
- optional agent-review summary over deterministic findings

The deterministic scan is the source of truth.

The optional agent review is advisory only.

## Main security areas covered

At the product level, the MVP surfaces these major families:

- Prompt injection
- Data exfiltration
- Privilege escalation
- Supply chain risk
- Excessive agency
- Dangerous execution
- Malware signatures
- MCP hygiene

The backend scanner contains a larger deterministic rule registry underneath these visible product groupings.

## Product architecture

### Frontend

`frontend/` contains the Next.js app.

Responsibilities:

- collect scan targets
- choose deterministic-only vs deterministic + agent review
- manage OpenRouter BYOK settings in the browser
- poll scan state
- render dashboards, findings, and report downloads

### Backend

`SkillSpector/` contains the FastAPI backend and the scanner engine.

Responsibilities:

- validate scan targets
- queue and persist scans
- run deterministic scanning
- optionally run bounded agent review
- persist findings, reports, and scan events
- serve frontend-facing API routes

### Persistence

The current MVP uses SQLite.

Persisted data includes:

- scan metadata
- findings
- reports
- scan events
- agent review payloads

## Main API routes

### Health and version

- `GET /health`
- `GET /v1/version`

### Scan lifecycle

- `POST /v1/scans`
- `GET /v1/scans`
- `GET /v1/scans/{scan_id}`
- `GET /v1/scans/{scan_id}/events`

### Findings and reports

- `GET /v1/scans/{scan_id}/findings`
- `GET /v1/scans/{scan_id}/reports`
- `GET /v1/scans/{scan_id}/reports/{fmt}`
- `GET /v1/scans/{scan_id}/share-summary`

### Optional agent review

- `GET /v1/scans/{scan_id}/agent-review`

### Rule registry

- `GET /v1/rules`
- `GET /v1/rules/{rule_id}`

### OpenRouter model catalog

- `GET /v1/providers/openrouter/models`

## Repository structure

```text
skill-spec/
├─ .git/                    # root Git repository
├─ Dockerfile               # single-image build for frontend + backend + proxy
├─ .dockerignore            # root Docker build ignore file
├─ deploy/                  # single-container VPS deploy files
├─ docs/                    # plans, reports, mockups, demo assets
├─ frontend/                # Next.js frontend
├─ SkillSpector/            # backend + scanner engine
└─ README.md                # this file
```

### Frontend structure

```text
frontend/
├─ app/
│  ├─ components/           # reusable UI components
│  ├─ lib/                  # API client and browser-side helpers
│  ├─ scans/                # scan routes
│  ├─ globals.css           # theme + global styles
│  ├─ layout.tsx            # app shell
│  └─ page.tsx              # landing page
├─ package.json
├─ next.config.ts
└─ tsconfig.json
```

Important frontend files:

- `frontend/app/page.tsx`
- `frontend/app/scans/[scanId]/page.tsx`
- `frontend/app/components/scan-console.tsx`
- `frontend/app/components/byok-settings-modal.tsx`
- `frontend/app/components/report-download-menu.tsx`
- `frontend/app/components/info-popover.tsx`
- `frontend/app/lib/api.ts`
- `frontend/app/lib/byok-settings.ts`

### Backend structure

```text
SkillSpector/
├─ src/skillspector/
│  ├─ agent_review/         # bounded post-scan agent review
│  ├─ api/                  # FastAPI application layer
│  ├─ nodes/                # analyzer and graph nodes
│  ├─ providers/            # model/provider integrations
│  ├─ graph.py              # scanner graph entrypoint
│  ├─ state.py              # shared state definitions
│  └─ ...
├─ tests/
├─ Dockerfile
├─ docker-compose.yml
├─ pyproject.toml
└─ README.md
```

Important backend files:

- `SkillSpector/src/skillspector/api/main.py`
- `SkillSpector/src/skillspector/api/store.py`
- `SkillSpector/src/skillspector/api/scanner.py`
- `SkillSpector/src/skillspector/api/worker.py`
- `SkillSpector/src/skillspector/api/guardrails.py`
- `SkillSpector/src/skillspector/api/presentation.py`
- `SkillSpector/src/skillspector/api/byok.py`
- `SkillSpector/src/skillspector/api/openrouter.py`
- `SkillSpector/src/skillspector/agent_review/graph.py`

### Deploy structure

```text
deploy/
├─ compose.single.vps.yml    # single-container VPS stack
├─ Caddyfile.single          # internal routing
├─ supervisord.single.conf   # process manager config
└─ .env.single.example       # deploy-time environment template
```

## Local development

### Requirements

Frontend:

- Node.js 20+
- npm

Backend:

- Python 3.12+
- `uv` recommended

### Run frontend locally

```powershell
cd frontend
npm install
$env:NEXT_PUBLIC_API_URL="http://localhost:8000"
npm run dev
```

Frontend local URL:

```text
http://localhost:3000
```

### Run backend locally

```powershell
cd SkillSpector
uv venv .venv
.venv\Scripts\activate
uv sync --all-extras
skillspector-api
```

Backend local URL:

```text
http://localhost:8000
```

### Local demo workflow

1. Start the backend
2. Start the frontend
3. Open:

```text
http://localhost:3000
```

The frontend talks to:

```text
http://localhost:8000
```

## Single-container VPS deployment

This is the primary deploy path for the current MVP.

It packages:

- Next.js frontend
- FastAPI backend
- embedded worker
- internal Caddy reverse proxy

into one container.

External port:

- `80`

Internal routing:

- `/` → frontend
- `/api/*` → backend API
- `/health` → backend health

### Why this is the current recommended deploy

- simplest founder-demo setup
- one VPS
- one container
- one command
- avoids cross-process BYOK issues from separate worker deployment

### Prerequisites

Install on the VPS:

- Docker Engine
- Docker Compose plugin

### Deploy steps

From the repo root on the VPS:

```bash
git clone <your-repo-url>
cd skill-spec
cp deploy/.env.single.example deploy/.env.single
docker compose \
  --env-file deploy/.env.single \
  -f deploy/compose.single.vps.yml \
  up -d --build
```

### Environment file

Current default template:

```text
SKILLSPECTOR_CORS_ORIGINS=*
SKILLSPECTOR_MAX_SCAN_TIMEOUT_SECONDS=300
```

### What runs inside the container

The single image runs three processes under Supervisor:

- backend API on `127.0.0.1:8000`
- frontend Next.js server on `127.0.0.1:3000`
- Caddy on `:80`

### Persistence

The single-container compose file creates:

- `skillspector_data` — SQLite database volume
- `skillspector_work` — temp scan workspace volume

SQLite path inside the container:

```text
/data/skillspector.db
```

### Build the image directly

If you just want the image build recipe, use the root Dockerfile:

```bash
docker build -t superalign-skill-scanner .
```

Run it directly:

```bash
docker run --rm -p 80:80 -v skillspector_data:/data -v skillspector_work:/tmp/skillspector-scans superalign-skill-scanner
```

### Verify deployment

```bash
docker compose --env-file deploy/.env.single -f deploy/compose.single.vps.yml ps
docker compose --env-file deploy/.env.single -f deploy/compose.single.vps.yml logs -f app
curl http://your-vps-ip/health
```

### Update deployment

```bash
git pull
docker compose \
  --env-file deploy/.env.single \
  -f deploy/compose.single.vps.yml \
  up -d --build
```

## Current MVP constraints

### Good enough for now

- founder demos
- internal scanning
- single-VPS deployment
- deterministic install-risk review
- optional BYOK agent assistance

### Not yet hardened as public SaaS

- no product-grade auth or tenant isolation
- SQLite instead of a multi-tenant production DB
- local-path scanning is okay for internal use, not ideal for public exposure
- BYOK browser storage is acceptable for MVP, not ideal for hardened public deployment
- backend should sit behind VPN, Cloudflare Access, or another access gate if used beyond trusted environments

## Repo hygiene notes

- This root repo is the only Git repo that should be used going forward.
- Nested Git metadata from earlier subprojects was archived under `.repo-admin/` and is ignored.
- Generated directories such as `frontend/.next/`, `frontend/node_modules/`, `SkillSpector/.venv/`, and temp scan workspaces are ignored from version control.
- The backend directory keeps the name `SkillSpector/` to avoid breaking inherited paths and imports.

## Related docs

- `SkillSpector/README.md` — backend/scanner engine reference
- `docs/plans/` — implementation plans
- `docs/reports/` — product and scan-related documentation
- `docs/mockups/` — UI references
