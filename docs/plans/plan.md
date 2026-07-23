# Backend Implementation Plan: AI Skill Checker MVP

## Goal

Build a FastAPI and Docker backend for an AI skill checker. The MVP must first support deterministic-only scanning and show every report possible from deterministic checks. Optional BYOK LLM scanning comes after the deterministic scan path is working.

The backend should reuse the existing SkillSpector LangGraph scanner instead of rewriting the analyzer pipeline.

Core defaults:

- Frontend: Next.js, outside this backend plan
- Backend API: FastAPI
- Scanner runtime: existing SkillSpector LangGraph workflow
- Job model: async scan jobs
- MVP storage: SQLite on a Docker volume
- Runtime packaging: Docker Compose
- Default scan mode: deterministic-only
- Optional scan mode: deterministic plus BYOK LLM
- BYOK credential handling: per scan, never stored

## Phase 1: Backend API Skeleton and Docker Runtime

### Objective

Create a production-shaped FastAPI service that can run inside Docker and expose basic health and version endpoints.

### Implementation

Add a new API package under the existing Python project:

- `skillspector.api.main`
- `skillspector.api.schemas`
- `skillspector.api.config`

Add FastAPI dependencies:

- `fastapi`
- `uvicorn[standard]`

Add Docker support:

- update or extend the Dockerfile with an API target
- add `docker-compose.yml`
- mount persistent data at `/data`
- mount temporary scan workspace at `/tmp/skillspector-scans`

Expose:

- `GET /health`
- `GET /v1/version`

Expected health response:

```json
{
  "status": "ok",
  "service": "skillspector-api",
  "scanner_version": "2.4.2"
}
```

### Testable Parameters

- `docker compose up api` starts the FastAPI server successfully.
- `GET /health` returns HTTP `200`.
- `GET /health` includes `status: ok`.
- `GET /v1/version` returns the installed SkillSpector version.
- API container runs without requiring any LLM API key.
- Existing `skillspector` CLI still works after adding API dependencies.

## Phase 2: Deterministic Scan Job API

### Objective

Create the async scan-job API for deterministic-only scans. The API should accept a GitHub repo URL, local path, zip path, or single skill file and enqueue a scan.

### Implementation

Add SQLite-backed persistence:

- `skillspector.api.store`
- `skillspector.api.worker`
- `skillspector.api.scanner`

Create tables:

- `scans`
- `scan_reports`
- `scan_findings`
- `scan_events`

Expose:

- `POST /v1/scans`
- `GET /v1/scans/{scan_id}`

Initial request body:

```json
{
  "target": "https://github.com/org/repo",
  "mode": "deterministic",
  "formats": ["json", "markdown", "sarif", "terminal"]
}
```

Initial create response:

```json
{
  "scan_id": "uuid",
  "status": "queued",
  "mode": "deterministic"
}
```

Supported statuses:

- `queued`
- `running`
- `completed`
- `failed`
- `canceled`

The worker must invoke the existing graph with:

```python
await graph.ainvoke({
    "input_path": target,
    "output_format": "json",
    "use_llm": False
})
```

For MVP, run one graph invocation per requested format so the existing report formatter remains the source of truth.

### Testable Parameters

- `POST /v1/scans` creates a row in SQLite.
- New scans start with status `queued`.
- Worker picks up queued scans and changes status to `running`.
- Completed scans end with status `completed`.
- Failed scans end with status `failed` and store an error message.
- Deterministic scan always invokes the graph with `use_llm: false`.
- A scan can run without `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or any other LLM credential.
- A known safe fixture returns a low score or no findings.
- A known malicious fixture returns at least one deterministic finding.

## Phase 3: Deterministic Reports and Finding Normalization

### Objective

Store and expose every deterministic report format and normalized finding data for the frontend.

### Implementation

Expose:

- `GET /v1/scans/{scan_id}/findings`
- `GET /v1/scans/{scan_id}/reports/json`
- `GET /v1/scans/{scan_id}/reports/markdown`
- `GET /v1/scans/{scan_id}/reports/sarif`
- `GET /v1/scans/{scan_id}/reports/terminal`

Normalize each finding into this API shape:

```json
{
  "id": "AST1",
  "category": "Dangerous Code Execution",
  "pattern": "exec() call detected",
  "severity": "HIGH",
  "confidence": 0.85,
  "location": {
    "file": "scripts/helper.py",
    "start_line": 12,
    "end_line": null
  },
  "finding": "exec(user_input)",
  "explanation": "Direct exec() call allows arbitrary code execution.",
  "remediation": "Replace exec() with a safe alternative.",
  "code_snippet": "...",
  "tags": []
}
```

The deterministic MVP must surface these rule families:

- `P1-P8`
- `E1-E5`
- `PE1-PE5`
- `SC1-SC7`
- `TR1-TR3`
- `EA1-EA4`
- `OH1-OH3`
- `MP1-MP3`
- `TM1-TM4`
- `RA1-RA2`
- `AS1-AS3`
- `AR1-AR3`
- `SSRF1-SSRF3`
- `AST1-AST9`
- `TT1-TT5`
- `YR1-YR4`
- `LP1-LP4`
- `TP1-TP3`
- `RP1-RP3`

Exclude from deterministic mode:

- `TP4`
- `SSD-*`
- `SDI-*`
- `SQP-*`
- LLM meta-analysis confirmation

Each completed scan summary should include:

- target
- status
- mode
- risk score
- severity
- recommendation
- safe-to-install boolean
- total findings
- findings by severity
- findings by category
- report formats available

### Testable Parameters

- JSON report endpoint returns valid JSON.
- Markdown report endpoint returns `text/markdown`.
- SARIF report endpoint returns valid SARIF JSON.
- Terminal report endpoint returns plain text.
- `GET /v1/scans/{scan_id}/findings` returns normalized finding objects.
- Every finding includes rule ID, severity, confidence, file, and start line.
- Completed scan summary includes risk score, severity, recommendation, and safe-to-install.
- Deterministic mode response contains `scan_mode: static-only`.
- Deterministic mode metadata contains `llm_requested: false` and `llm_used: false`.
- No deterministic scan result depends on LLM availability.

## Phase 4: Optional BYOK LLM Scan

### Objective

Add optional LLM scanning after deterministic scanning works. BYOK credentials must be passed per scan and never stored.

### Implementation

Extend `POST /v1/scans`:

```json
{
  "target": "https://github.com/org/repo",
  "mode": "deterministic+llm",
  "formats": ["json", "markdown", "sarif"],
  "llm": {
    "provider": "openai",
    "model": "gpt-4.1-mini",
    "api_key": "runtime-only",
    "base_url": null
  }
}
```

Supported MVP providers:

- OpenAI-compatible HTTP provider first
- additional providers later

Credential handling:

- API key is accepted only in the request body.
- API key is kept in memory only while the worker runs the job.
- API key is never stored in SQLite.
- API key is never written to logs.
- API key is never included in reports.

Implementation detail:

Do not set global process environment variables for BYOK credentials because concurrent scans could leak credentials across jobs. Use Python `contextvars` or an equivalent request-scoped credential mechanism, and make LLM credential resolution prefer request-scoped credentials over environment variables.

LLM-enabled scan should invoke:

```python
await graph.ainvoke({
    "input_path": target,
    "output_format": selected_format,
    "use_llm": True
})
```

LLM findings and enrichment may include:

- `TP4`
- `SSD-*`
- `SDI-*`
- `SQP-*`
- LLM meta-analysis filtering and remediation enrichment

Important security rule:

High and critical deterministic findings must not be silently removed just because the LLM disagrees.

### Testable Parameters

- A deterministic scan still works when no LLM key is provided.
- A `deterministic+llm` scan without an LLM key is rejected with HTTP `400`.
- BYOK API key does not appear in SQLite.
- BYOK API key does not appear in logs.
- BYOK API key does not appear in JSON, Markdown, SARIF, or terminal reports.
- LLM mode response contains `scan_mode: static+llm`.
- LLM mode response contains `llm_requested: true`.
- If the LLM call fails, the scan still returns deterministic findings.
- If all LLM calls fail, the report marks the scan as degraded.
- High and critical deterministic findings survive LLM filtering.

## Phase 5: Hardening, Observability, and Frontend Readiness

### Objective

Make the backend reliable enough for a Next.js frontend and safe enough for internal MVP usage.

### Implementation

Add runtime limits:

- max scan timeout
- max upload size
- max clone duration
- max files per scan
- max file size per scan
- max concurrent worker jobs

Add observability:

- structured logs
- scan events
- scan duration
- failure reason
- analyzer mode metadata
- OSV fallback warning when live dependency lookup is unavailable

Add frontend support:

- CORS config for local Next.js
- stable response schemas
- status polling endpoint
- finding filters by severity/category/rule/file
- report download endpoints

Add security controls:

- Git host allowlist
- download host allowlist
- SSRF protection from existing `InputHandler`
- temp directory cleanup
- non-root Docker user
- no Docker socket mount
- no execution of scanned skill code

Add documentation:

- backend local setup
- Docker Compose setup
- API examples
- deterministic vs LLM mode explanation
- BYOK privacy note

### Testable Parameters

- API supports polling from a frontend until scan completion.
- CORS allows configured Next.js origin.
- Large or unsupported inputs fail with clear errors.
- Private/internal URLs are blocked.
- Temporary clone/download directories are cleaned after scan completion.
- Restarting Docker containers does not delete completed scan reports.
- Logs include scan ID and status transitions.
- Logs do not include secrets.
- API OpenAPI docs load at `/docs`.
- End-to-end test can create a scan, wait for completion, fetch findings, and fetch all reports.
- Existing CLI and MCP behavior remain compatible.

## Final MVP Definition

The MVP is complete when a user can:

1. Submit a GitHub repo or skill path to the FastAPI backend.
2. Run a deterministic-only scan without any LLM credentials.
3. See risk score, severity, recommendation, and normalized findings.
4. Download JSON, Markdown, SARIF, and terminal reports.
5. Optionally submit a BYOK LLM scan.
6. Verify that BYOK credentials are never stored.
7. Run the whole backend through Docker Compose.

