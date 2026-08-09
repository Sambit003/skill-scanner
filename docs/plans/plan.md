# Deterministic Skill Scanner Plan

## Goal

Provide a deployable FastAPI, Celery, and Next.js application around the ScanKernel deterministic scanner.

## Product boundary

- Accept Git URLs, local directories, archives, and skill manifests.
- Never execute scanned code.
- Keep scan behavior reproducible and independent of external model services.
- Produce JSON, Markdown, SARIF, and terminal reports.
- Preserve high-severity findings and expose filtering decisions in report metadata.

## Runtime design

The backend creates a queued scan, dispatches a Celery task, and records lifecycle state in PostgreSQL. The worker invokes the native scanner pipeline:

1. Resolve input.
2. Build file and manifest context.
3. Run pattern, AST, taint, YARA, supply-chain, and MCP checks.
4. Apply deterministic confidence filtering.
5. Compute risk, apply baselines, and render reports.

The frontend starts scans, polls status, displays summaries and findings, and links to each report format.

## API contract

Create a scan:

```json
{
  "target": "https://github.com/example/skill",
  "asset_type": "agent_skill"
}
```

Core routes:

- `POST /v1/scans`
- `GET /v1/scans/{scan_id}`
- `GET /v1/scans/{scan_id}/findings`
- `GET /v1/scans/{scan_id}/reports`
- `GET /v1/scans/{scan_id}/reports/{format}`
- `GET /v1/rules`
- `GET /v1/rules/{rule_id}`

## Acceptance criteria

- The application starts with `docker compose up --build`.
- A scan completes without external credentials.
- No scan content leaves the scanner runtime.
- Report formats agree on findings and risk score.
- The frontend can start and inspect a completed scan.
- Python compilation, frontend lint, frontend build, and a direct scanner smoke test pass.
