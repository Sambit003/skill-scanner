# AI Skill Scanner Demo

This project is a deterministic security scanner for AI Agent Skills. The core
scanner, analyzers, rule catalog, YARA integration, report generation, and CLI
are implemented in Go. Python is used only by the web application's FastAPI API
and Celery worker to schedule scans, invoke the Go executable, and persist the
results.

The scanner accepts a Git URL, local directory, ZIP archive, or skill manifest
and produces JSON, Markdown, SARIF, or terminal reports. It never executes the
code being scanned and does not send scan content to an LLM service.

## Repository layout

| Path | Purpose |
| --- | --- |
| `apps/frontend/` | Next.js scan dashboard |
| `apps/backend/` | FastAPI API and Celery orchestration worker |
| `packages/scan_kernel/` | Go 1.26.1 scanning engine and plugin build profiles |
| `contracts/scan-kernel/v1/`, `v2/` | Language-neutral scanner process contracts |
| `docker-compose.yml` | Local PostgreSQL, Redis, API, worker, and frontend stack |

[Moon](https://moonrepo.dev/) manages the monorepo task graph. pnpm manages the
frontend, uv manages the Python web services, and Go owns the complete scanning
path.

## Quick start with Docker Compose

This is the simplest way to run the complete application. It requires Git,
Docker Desktop or Docker Engine, Docker Compose, and Docker Buildx.

```bash
docker compose up -d --build
docker compose ps
```

Wait until all five services report `healthy`, then open:

- Dashboard: http://localhost:3000
- API documentation: http://localhost:8000/api/v1/docs
- API health: http://localhost:8000/api/v1/health

Submit a Git repository from the dashboard, or create a scan through the API:

```bash
curl -X POST http://localhost:8000/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "https://github.com/mattpocock/skills",
    "asset_type": "agent_skill",
    "scan_scope": "skill_folders",
    "include_readme": false
  }'
```

The response contains a `scan_id`. Use it to retrieve the status and reports:

```bash
curl http://localhost:8000/v1/scans/<scan_id>
curl http://localhost:8000/v1/scans/<scan_id>/findings
curl http://localhost:8000/v1/scans/<scan_id>/reports/json
curl http://localhost:8000/v1/scans/<scan_id>/reports/sarif
```

View logs or stop the stack with:

```bash
docker compose logs -f backend-api backend-worker
docker compose down
```

PostgreSQL and Redis data are retained in named volumes. To remove those local
development volumes as well, use `docker compose down --volumes` only when the
stored scan history is no longer needed.

## Developer setup with Moon

On macOS, install [proto](https://moonrepo.dev/proto) with Homebrew before
running any repository setup commands:

```bash
brew install proto
proto setup
exec "$SHELL" -l
proto --version
```

`proto setup` adds proto-managed binaries to your shell environment. The
`exec` command reloads the login shell immediately; opening a new terminal does
the same thing.

The checked-in `.prototools` file pins the development toolchain:

- Moon 2.4
- Node.js 24
- pnpm 11.18
- Python 3.12
- uv 0.10
- Go 1.26.1

After installing proto, run the following commands from the repository root to
install the pinned tools and project dependencies:

```bash
proto install
moon setup
moon run workspace:setup
```

Run the complete repository validation before opening a pull request:

```bash
moon run workspace:check
```

Useful project tasks:

```bash
moon run frontend:dev
moon run frontend:lint
moon run frontend:build

moon run backend:check
moon run backend:test
moon run backend:integration

moon run scan-kernel:check
moon run scan-kernel:test
moon run scan-kernel:contract
moon run scan-kernel:smoke
moon run scan-kernel:regression
```

Run the full application in the foreground through Moon with:

```bash
moon run workspace:dev
```

Moon caches deterministic tasks locally. Remote caching is not configured.

## Run the Go scanner directly

Build a local developer executable:

```bash
moon run scan-kernel:build
```

The executable is written to:

```text
packages/scan_kernel/dist/dev/scan-kernel-engine
```

Examples:

```bash
# Scan a local skill and print a terminal report.
./packages/scan_kernel/dist/dev/scan-kernel-engine \
  scan --type skill --format terminal ./path/to/skill

# Produce JSON without remote target resolution.
./packages/scan_kernel/dist/dev/scan-kernel-engine \
  scan --type skill --format json --offline ./path/to/skill.zip

# Scan discovered skill folders in a Git repository. README files are excluded by default.
./packages/scan_kernel/dist/dev/scan-kernel-engine \
  scan --type skill --format json https://github.com/example/skills.git

# Scan every eligible repository file and explicitly include README files.
./packages/scan_kernel/dist/dev/scan-kernel-engine \
  scan --type skill --scope repository --include-readme --format json \
  https://github.com/example/skills.git

# Use additional YARA rules with a native-YARA build.
./scan-kernel-engine \
  scan --type skill --format sarif --yara-rules ./rules ./path/to/skill

# Inspect scanner and rule metadata.
./packages/scan_kernel/dist/dev/scan-kernel-engine version --json
./packages/scan_kernel/dist/dev/scan-kernel-engine rules list
./packages/scan_kernel/dist/dev/scan-kernel-engine rules show P1

# Create a suppression baseline from the current findings.
./packages/scan_kernel/dist/dev/scan-kernel-engine \
  baseline --offline --output .scan_kernel-baseline.yaml ./path/to/skill
```

The ordinary local Go build uses the explicit developer signature fallback. It
is useful for development and fast tests, but it is not parity-certified for
YARA behavior. Use a certified Linux bundle for customer delivery.

## Build a customer bundle

The checked-in `skill` profile contains only the `agent_skill` plugin. Its
compile-time tags exclude scanners that are not part of that profile, producing
a dedicated Agent Skill scanner for distribution to another team.

For HSBC-facing delivery, use the `hsbc` profile. It builds the same Agent Skill
scanner with dependency advisory checks disabled:

```bash
moon run workspace:bundle-hsbc -- --version 1.0.0
```

Build both supported customer targets:

```bash
moon run workspace:bundle-skill -- --version 1.0.0
```

Equivalent direct command:

```bash
./packages/scan_kernel/scripts/build-scanner.sh \
  --profile skill \
  --version 1.0.0
```

The default build produces:

```text
packages/scan_kernel/dist/bundles/skill/1.0.0/
├── linux-amd64/
├── linux-arm64/
├── scan-kernel-skill-1.0.0-linux-amd64.tar.gz
├── scan-kernel-skill-1.0.0-linux-arm64.tar.gz
└── SHA256SUMS
```

Each target directory and archive contains:

- one `scan-kernel-engine` executable;
- `manifest.json` with the profile, target, plugin, build, and parity metadata;
- `SHA256SUMS`;
- Go dependency notices; and
- the YARA license.

Customer bundles are Linux-only and currently support `linux/amd64` and
`linux/arm64`. They pin Go 1.26.1 and YARA 4.5.4. YARA and its required native
libraries are statically linked, so the target machine does not need Go,
Python, libyara, or a C runtime package installed.

Build only one architecture when required:

```bash
./packages/scan_kernel/scripts/build-scanner.sh \
  --profile skill \
  --version 1.0.0 \
  --targets linux/amd64
```

Verify the generated archives:

```bash
cd packages/scan_kernel/dist/bundles/skill/1.0.0
shasum -a 256 -c SHA256SUMS
```

After extracting the archive on the target Linux host:

```bash
tar -xzf scan-kernel-skill-1.0.0-linux-amd64.tar.gz
cd linux-amd64
shasum -a 256 -c SHA256SUMS
chmod +x scan-kernel-engine
./scan-kernel-engine version --json
./scan-kernel-engine scan --offline --format json ./path/to/skill
```

The version response for a distribution bundle should include only operational
build and runtime metadata:

```json
{
  "go_version": "go1.26.1",
  "plugins": ["agent_skill"],
  "yara_mode": "native-static",
  "yara_version": "4.5.4"
}
```

Regression evidence remains internal to the test harness and is not embedded
in the executable or bundle manifest.

### Developer-only fallback bundle

The fallback must be selected explicitly. It is not suitable for release
regression validation of native-YARA behavior:

```bash
./packages/scan_kernel/scripts/build-scanner.sh \
  --profile skill \
  --version dev \
  --targets "$(go env GOOS)/$(go env GOARCH)" \
  --yara fallback
```

## Verify scanner regressions

The regression test uses the pinned `mattpocock/skills` commit
`84fdeffd12f2ee307994d1eb6feb48173b6e0502`. It compares all user-visible
finding fields and the complete summary against the checked-in golden result.
The same task can host additional corpora for other plugins and asset types.

Run the developer regression gate:

```bash
moon run scan-kernel:regression
```

To avoid fetching the fixture again, pass an existing checkout:

```bash
./packages/scan_kernel/scripts/verify-regression.sh \
  /path/to/mattpocock-skills
```

On Linux, pass a native-YARA executable to also compare the complete, ordered
14-finding malicious fixture payload:

```bash
SCAN_KERNEL_BINARY=/path/to/scan-kernel-engine \
  ./packages/scan_kernel/scripts/verify-regression.sh \
  /path/to/mattpocock-skills
```

The regression gate covers YARA findings, AST and taint source spans, explicit
JSON nulls, finding ordering, scanner version, and category/severity totals.

## Scanner process contract

The API and worker never import scanner implementation modules. They communicate
with `scan-kernel-engine` through protocol v2:

1. The worker starts the executable.
2. It writes one JSON request to standard input.
3. It reads one JSON response from standard output.
4. Diagnostic logs are written to standard error.

Protocol v2 adds explicit `scan_scope` and `include_readme` fields. Protocol v1
remains available with its legacy whole-repository, README-included behavior.
Both versions support `scan`, `list_rules`, and `get_rule`. Findings, including
critical findings, are successful results. Invalid requests exit with status
`2`; scanner execution failures exit with status `3`.

The Compose backend image installs the statically linked scanner at:

```text
/usr/local/bin/scan-kernel-engine
```

Verify the scanner inside the running API container:

```bash
docker compose exec -T backend-api \
  /usr/local/bin/scan-kernel-engine version --json
```

## HTTP API

The API is available under both `/api/v1` and `/v1`. The frontend uses `/v1`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Service health |
| `POST` | `/v1/scans` | Queue a scan |
| `GET` | `/v1/scans` | List scans |
| `GET` | `/v1/scans/{scan_id}` | Poll status and retrieve the result |
| `GET` | `/v1/scans/{scan_id}/findings` | Retrieve or filter findings |
| `GET` | `/v1/scans/{scan_id}/reports` | List report downloads |
| `GET` | `/v1/scans/{scan_id}/reports/{format}` | Download a report |
| `GET` | `/v1/rules` | List scanner rules |
| `GET` | `/v1/rules/{rule_id}` | Retrieve one rule |

Supported report formats are `json`, `markdown`, `sarif`, and `terminal`.

Finding identifiers have two distinct purposes:

- `id` is the persisted database UUID for one finding record;
- `rule_id` is the scanner rule identifier displayed to users, such as `P1`,
  `AST4`, or `RP1`.

## Troubleshooting

### The dashboard says it cannot reach the backend

Confirm that the API is healthy and port `8000` is reachable:

```bash
docker compose ps
curl http://localhost:8000/api/v1/health
docker compose logs --tail=100 backend-api backend-worker
```

If source code changed after the containers were created, rebuild and recreate
the services:

```bash
docker compose up -d --build --force-recreate
```

The local frontend expects `NEXT_PUBLIC_API_URL=http://localhost:8000`. For a
hosted deployment, configure the public API URL and allowed CORS origins for the
actual domains before building the frontend image.

### A previous scan still shows old findings

Completed scan rows are immutable snapshots. Rebuilding the scanner does not
rewrite historical results. Submit a new scan after rebuilding the API and
worker.

### The native bundle cannot run on macOS or Windows

Certified bundles are Linux executables. Select the architecture of the target
Linux host (`linux/amd64` or `linux/arm64`). Use the explicit fallback only for
local development on other operating systems.

### Moon cannot find a pinned executable

Provision the repository toolchains again, then rerun setup:

```bash
proto install
moon setup
moon run workspace:setup
```

### Ports are already in use

The local stack binds ports `3000`, `8000`, `5432`, and `6379`. Stop the
conflicting local process or change the corresponding host-side port mapping in
`docker-compose.yml`.

## Security and deployment notes

- `docker-compose.yml` is a local/demo configuration. Replace its database
  password and `SECRET_KEY` before using the services outside a trusted local
  environment.
- Scanned source is processed locally by the Go executable. The HSBC profile
  disables dependency advisory checks; `--offline` also rejects remote target
  resolution.
- The application Compose file intentionally does not manage a Cloudflare
  Tunnel. Run externally managed ingress or tunnel services separately.
