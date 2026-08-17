# Deterministic Skill Scanner Plan

## Goal

Provide a deployable FastAPI, Celery, and Next.js application around the deterministic scanner.

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
3. Dispatch to the compile-time Agent Skill plugin and run deterministic pattern,
   behavioral, taint, signature, supply-chain, and MCP-oriented checks in Go.
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
- Customer-facing report formats agree on findings, severity, recommendation,
  and install verdict without exposing a numeric score.
- The frontend can start and inspect a completed scan.
- Go formatting, vet, tests and protocol contracts pass alongside backend tests,
  frontend lint/build, Docker configuration, and a direct binary smoke test.
- The pinned scanner corpus passes `moon run scan-kernel:regression`:
  the readable identity fields, every user-visible finding field, severity/category
  breakdowns, recommendation, install verdict, and internal scanner score must match.
- The Compose scanner uses native YARA with stable bundled-rule namespaces,
  metadata overrides, match snippets, and custom-rule loading behavior.
- The skill-only profile produces six target archives with manifests, checksums,
  and dependency notices.
