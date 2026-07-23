# SuperAlign Skill Scanner

Monorepo for the SuperAlign Skill Scanner MVP.

This product is a founder-demo / internal-use scanner for AI agent skills and skill repositories. It answers a simple question:

> Is this repo safe enough to review or install?

The current MVP is deterministic first, with an optional bounded agent review pass on top. It does not execute the target repository code.

## What this product is

This repo contains:

- a Next.js frontend for submitting scans and reviewing results
- a FastAPI backend that queues and runs scans
- a deterministic security scanner built on top of the `SkillSpector` engine
- an optional BYOK OpenRouter review flow for post-scan agent triage
- deployment files for a simple VPS-based MVP setup

The product is designed for:

- founder demos
- internal security review
- quick triage of public GitHub skill repositories
- showing findings, risk score, categories, downloadable reports, and optional agent commentary

It is not positioned yet as a hardened public multi-tenant SaaS.

## Core behavior

### Deterministic by default

The main scan path is deterministic:

- static parsing
- pattern matching
- AST-based checks
- taint-style flow checks
- rule-based normalization into findings
- report generation

The deterministic pass is the authoritative result in the current product.

### Optional agent review

If enabled, the system can run a bounded post-scan review using a user-supplied OpenRouter API key.

That review:

- does not replace deterministic findings
- reviews findings and snippets after the deterministic scan
- helps classify likely false positives, duplicates, and follow-up actions
- is treated as a triage assistant, not the source of truth

## What the scanner checks

At the product level, the MVP surfaces these major families of checks:

- Prompt injection
- Data exfiltration
- Privilege escalation
- Supply chain risk
- Excessive agency
- Dangerous execution
- Malware signatures
- MCP hygiene

The landing page currently describes these as the visible product coverage areas, while the backend scanner contains a larger deterministic rule registry.

The underlying scanner supports deterministic rule families such as:

- prompt injection and hidden instructions
- credential and environment harvesting
- suspicious outbound transmission patterns
- unsafe code execution patterns
- tainted input flowing to dangerous sinks
- insecure MCP permissions and tool exposure
- unpinned or risky supply-chain references
- malicious signatures such as webshell/miner-like patterns

## What the product outputs

For each completed scan, the system can provide:

- scan status and scan timeline
- risk score
- severity and recommendation
- findings count
- findings grouped by severity
- findings grouped by category
- normalized finding list with file and line references
- finding details with explanation and remediation
- downloadable reports in:
  - JSON
  - Markdown
  - SARIF
  - Terminal/text
- optional agent review summary and structured review details

## Product architecture

### Frontend

The frontend is a Next.js app in `frontend/`.

Main responsibilities:

- collect scan target input
- let the user choose deterministic-only vs deterministic + agent review
- manage local OpenRouter BYOK settings in the browser
- poll the backend for scan status
- render dashboard cards, tables, charts, and finding detail panels
- trigger report downloads

### Backend API

The backend API is a FastAPI service in `SkillSpector/src/skillspector/api/`.

Main responsibilities:

- validate scan targets
- create and persist scan jobs
- run the deterministic scanner
- optionally run bounded agent review
- store scan summaries, findings, events, and reports
- expose frontend-facing endpoints

### Scanner engine

The scanner engine lives under `SkillSpector/src/skillspector/`.

It contains:

- graph/state orchestration
- deterministic analyzers
- report generation
- rule documentation defaults
- provider integrations
- optional agent-review logic

### Persistence

Current MVP persistence is SQLite.

The API stores:

- scan metadata
- reports
- findings
- scan events
- agent review summary payloads

For the recommended deploy, SQLite is stored in a Docker-backed persistent volume.

## Main API routes

The product currently exposes these backend routes:

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

### Rule documentation registry

- `GET /v1/rules`
- `GET /v1/rules/{rule_id}`

These power the inline frontend explanations and the rule-detail metadata.

### OpenRouter model catalog

- `GET /v1/providers/openrouter/models`

This is used by the frontend settings modal to help choose a model for optional agent review.

## Repository structure

## Top level

```text
skill-spec/
├─ .git/                    # root Git repository
├─ deploy/                  # VPS deployment files for the MVP
├─ docs/                    # plans, reports, mockups, demo assets
├─ frontend/                # Next.js frontend
├─ SkillSpector/            # backend + scanner engine
└─ README.md                # this file
```

## Frontend structure

```text
frontend/
├─ app/
│  ├─ components/           # reusable UI components
│  ├─ lib/                  # API client and browser-side settings helpers
│  ├─ scans/                # scan list and scan detail routes
│  ├─ globals.css           # theme and global styling
│  ├─ layout.tsx            # app shell
│  └─ page.tsx              # landing page
├─ package.json
├─ next.config.ts
└─ tsconfig.json
```

Important frontend files:

- `frontend/app/page.tsx` — landing page and coverage section
- `frontend/app/scans/[scanId]/page.tsx` — main scan dashboard
- `frontend/app/components/scan-console.tsx` — scan submission UI
- `frontend/app/components/byok-settings-modal.tsx` — OpenRouter settings
- `frontend/app/components/report-download-menu.tsx` — report download UI
- `frontend/app/components/info-popover.tsx` — small info-card popovers
- `frontend/app/lib/api.ts` — backend API client
- `frontend/app/lib/byok-settings.ts` — browser-stored OpenRouter settings

## Backend structure

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
├─ tests/                   # scanner and API tests
├─ Dockerfile
├─ docker-compose.yml       # original backend-local compose file
├─ pyproject.toml
└─ README.md                # upstream/backend-specific docs
```

Important backend files:

- `SkillSpector/src/skillspector/api/main.py` — FastAPI routes
- `SkillSpector/src/skillspector/api/store.py` — SQLite persistence
- `SkillSpector/src/skillspector/api/scanner.py` — deterministic scan runner
- `SkillSpector/src/skillspector/api/worker.py` — queue worker loop
- `SkillSpector/src/skillspector/api/guardrails.py` — target validation and cleanup
- `SkillSpector/src/skillspector/api/presentation.py` — frontend-facing enrichment and rule docs
- `SkillSpector/src/skillspector/api/byok.py` — in-memory BYOK secret vault
- `SkillSpector/src/skillspector/api/openrouter.py` — OpenRouter model catalog helper
- `SkillSpector/src/skillspector/agent_review/graph.py` — bounded agent review graph

## Deploy structure

```text
deploy/
├─ compose.vps.yml          # backend + HTTPS proxy stack
├─ Caddyfile                # reverse proxy config
└─ .env.vps.example         # deploy-time environment template
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
3. Open the app in the browser:

```text
http://localhost:3000
```

The frontend will call:

```text
http://localhost:8000
```

## Founder-demo deployment

The recommended current deploy shape is:

- frontend on Vercel
- backend on one VPS with Docker
- SQLite persisted with a Docker volume
- embedded worker enabled
- no separate worker container

Reason:

- the current BYOK review flow keeps the per-scan OpenRouter key in API-process memory
- for this MVP, the safest deploy is to let the API process also run the worker

### Deployment files in this repo

- `deploy/compose.vps.yml`
- `deploy/Caddyfile`
- `deploy/.env.vps.example`

## Vercel frontend deployment

Deploy `frontend/` as a normal Next.js project.

Set:

```text
NEXT_PUBLIC_API_URL=https://api.example.com
```

## VPS backend deployment

### Prerequisites

Install on the VPS:

- Docker Engine
- Docker Compose plugin

Prepare DNS:

- `app.example.com` → Vercel
- `api.example.com` → VPS public IP

### Deploy steps

From the repo root on the VPS:

```bash
git clone <your-repo-url>
cd skill-spec
cp deploy/.env.vps.example deploy/.env.vps
```

Edit `deploy/.env.vps`:

```text
SKILLSPECTOR_API_DOMAIN=api.example.com
SKILLSPECTOR_CORS_ORIGINS=https://app.example.com
SKILLSPECTOR_MAX_SCAN_TIMEOUT_SECONDS=300
```

Start the stack:

```bash
docker compose \
  --env-file deploy/.env.vps \
  -f deploy/compose.vps.yml \
  up -d --build
```

### What this stack starts

- `api` — FastAPI backend with embedded worker enabled
- `caddy` — HTTPS reverse proxy

Persistent volumes:

- `skillspector_data` — SQLite database storage
- `skillspector_work` — temporary scan workspace

### Verify backend

```bash
docker compose --env-file deploy/.env.vps -f deploy/compose.vps.yml ps
docker compose --env-file deploy/.env.vps -f deploy/compose.vps.yml logs -f api
curl https://api.example.com/health
```

## Updating the deployment

```bash
git pull
docker compose \
  --env-file deploy/.env.vps \
  -f deploy/compose.vps.yml \
  up -d --build
```

## Current MVP constraints

This README should be honest about current scope.

### Good enough for now

- founder demos
- internal scanning
- single-VPS deployment
- deterministic install-risk review
- optional BYOK agent assistance

### Not yet hardened as public SaaS

- no product-grade auth/tenant isolation
- SQLite rather than multi-tenant production DB
- local-path scanning is fine for internal use but not for public exposure
- BYOK browser storage is acceptable for MVP, not ideal for a hardened public product
- API should be placed behind VPN, Cloudflare Access, or another access gate if used beyond trusted internal/demo scenarios

## Repo hygiene notes

- This root repo is the only Git repo that should be used going forward.
- Nested Git metadata from earlier subprojects was archived under `.repo-admin/` and is ignored.
- Generated directories such as `frontend/.next/`, `frontend/node_modules/`, `SkillSpector/.venv/`, and temp scan workspaces are ignored from version control.
- The backend directory keeps the name `SkillSpector/` to avoid breaking paths, imports, and scripts inherited from the scanner engine.

## Related docs

- `SkillSpector/README.md` — backend/scanner engine reference
- `docs/plans/` — implementation plans
- `docs/reports/` — product and scan-related documentation
- `docs/mockups/` — UI references

