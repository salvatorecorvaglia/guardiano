<p align="center">
  <img src="resources/guardiano.svg" alt="Guardiano logo" width="96" height="96">
</p>

# Guardiano

**Self-hosted application vulnerability management platform**

**Guardiano** is a self-hosted application vulnerability management platform. Import reports from your security scanners, bring findings into one inventory, and track triage, ownership, remediation, and accepted risk across applications and teams. It supports SAST, software composition analysis (SCA), infrastructure as code (IaC), and dynamic application security testing (DAST). Run your scanners separately, then upload their results through the web interface or API.

## Features ✨

- Centralized findings with deduplication, scan history, comparisons, and automatic reopening and resolution.
- Assets, products, teams, and access roles: administrator, manager, analyst, and viewer.
- Severity and risk prioritization, remediation SLAs, CISA KEV and EPSS enrichment.
- Risk acceptance with expiry, optional approval requirements, and audit history.
- Component inventory, license policies, SBOM and VEX support.
- CI quality gates and branch previews that evaluate reports without changing the findings inventory.
- Jira, GitHub, and GitLab issue integrations, outbound webhooks, and optional email notifications.
- Local authentication, two-factor authentication, OpenID Connect SSO, and scoped API tokens.

## Quick Start 🚀

Install Docker with the Compose plugin, then run these commands from the repository root:

```bash
cp .env.example .env
docker compose up --build -d
```

If you already have a `.env` file, keep it and review any new settings in [.env.example](.env.example).

Open <http://localhost:8080>. On an empty database, Guardiano creates the first administrator using `GUARDIANO_ADMIN_EMAIL` and `GUARDIANO_ADMIN_PASSWORD`. The example file supplies `admin@example.com` / `ChangeMe-Admin-2026!` for local evaluation; replace these values before starting any shared installation.

| Service | Local address |
| --- | --- |
| Web interface | <http://localhost:8080> |
| API | <http://localhost:8080/api/v1> |
| Interactive API documentation | <http://localhost:8080/api/docs> |
| PostgreSQL | `localhost:5432` (loopback only) |

API documentation is disabled when `ENV=production`.

```bash
docker compose ps
docker compose logs -f backend worker
docker compose down
```

Database data persists in the `pgdata` volume when the stack is stopped. `docker compose down -v` deletes that volume and its data.

For optional demo data on a development installation:

```bash
docker compose exec backend python -m app.cli seed-demo
```

## Import scan results

Create or select an asset, upload a report, and review the resulting findings. Guardiano detects supported formats automatically; the API also accepts an explicit format identifier.

| Report | Format identifier |
| --- | --- |
| SARIF 2.1.0 | `sarif` |
| CycloneDX JSON | `cyclonedx` |
| Trivy JSON | `trivy` |
| Semgrep JSON | `semgrep` |
| Grype JSON | `grype` |
| OSV-Scanner JSON | `osv` |
| OWASP Dependency-Check JSON | `dependency-check` |
| npm audit JSON | `npm-audit` |
| Gitleaks JSON | `gitleaks` |
| Checkov JSON | `checkov` |
| KICS JSON | `kics` |
| OWASP ZAP JSON | `zap` |
| Nuclei JSON or JSON Lines | `nuclei` |
| Guardiano JSON | `guardiano` |

For automated uploads, create an API token with the `ingest` scope and export it as `GUARDIANO_TOKEN`:

```bash
curl --fail-with-body http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer ${GUARDIANO_TOKEN}" \
  -F 'asset_name=my-service' \
  -F 'file=@report.sarif'
```

The asset is created if it does not exist and the caller has access to create it. Optional form fields include `format`, `scan_type`, `branch`, `commit_sha`, `preview`, and `close_missing`.

- Use `preview=true` to evaluate a report and its quality gate without updating the findings inventory. A branch different from an asset's configured default branch also implies preview mode.
- Use `close_missing=true` for complete default-branch reports to resolve findings from the same tool that are no longer reported. Empty reports do not close findings unless `allow_empty=true` is also supplied.
- Preview details and severity counts include auto-triage effects; each detailed finding also retains its
  `scanner_severity`. The optional `preview.would_resolve` count reports what `close_missing` would
  resolve without changing inventory. It is null for older previews that did not record this count.
- A successful upload returns HTTP 201. Check the response's `gate.passed` value separately to enforce a quality gate in CI; `gate` is null when no policy applies.

Ready-made CI integrations are available in [integrations/github-action](integrations/github-action/action.yml) and [integrations/gitlab](integrations/gitlab/guardiano.gitlab-ci.yml).

Asset and user selectors search in bounded pages and keep selected identities visible when searches
change. Existing `/assets/options` and `/users/directory` list APIs remain compatible; new clients can
use `/assets/options/search` and `/users/directory/search` with `q`, `page`, `page_size` (up to 100),
and `selected_id`. Search responses include a separate `selected` item so it need not match the page.
`/users/directory/lookup` resolves up to 500 explicit `ids` without downloading the directory.
Asset search and selection both enforce the caller's asset visibility.

## Configuration

[.env.example](.env.example) documents the available settings and defaults. The API and background worker share configuration.

| Settings | Purpose |
| --- | --- |
| `SECRET_KEY`, `INTEGRATIONS_KEY` | Session signing and encryption of stored integration credentials and MFA secrets |
| `GUARDIANO_ADMIN_EMAIL`, `GUARDIANO_ADMIN_PASSWORD` | First administrator bootstrap; only used when no users exist |
| `POSTGRES_*`, `DATABASE_URL` | Database connection; an explicit URL overrides the structured fields |
| `HTTP_PORT`, `PUBLIC_URL`, `REAL_IP_FROM` | Published port, public notification links, and trusted proxy CIDR |
| `MAX_UPLOAD_MB`, `MAX_REPORT_FINDINGS`, `MAX_CONCURRENT_INGESTS` | Report size, finding count, and ingestion concurrency limits |
| `SLA_*`, `RISK_ACCEPTANCE_*` | Remediation deadlines and risk acceptance policy |
| `OIDC_*`, `LOCAL_LOGIN`, `MFA_*` | SSO and local authentication policy |
| `SMTP_*` | Optional email delivery; email features remain hidden without `SMTP_HOST` |
| `INTEL_SYNC_ENABLED`, `OSV_API_URL` | Exploitability feed synchronization and advisory lookups |
| `OUTBOUND_ALLOW_HOSTS` | Explicitly permitted internal destinations for outbound integrations |
| `RETENTION_*`, `METRICS_*` | Record retention and optional Prometheus metrics |

Keep `INTEGRATIONS_KEY` persistent and independent of `SECRET_KEY`. Without it, encryption derives from `SECRET_KEY`, so rotating the signing key also makes stored credentials and MFA secrets unreadable. Back up configuration secrets separately from the database.

When upgrading an installation with existing SSO accounts, apply migrations, then explicitly bind
legacy identities to the **original** provider before allowing SSO traffic:

```bash
docker compose exec backend python -m app.cli bind-oidc-identities --legacy-issuer https://original-provider.example/realm
```

Use the exact issuer previously trusted by the installation, never a replacement provider.
The command is idempotent and revokes previous sessions for affected accounts. Unbound legacy
identities cannot sign in. Rehearse against a restored backup and retain local administrator
recovery access. To roll back this identity migration, restore a verified backup.

Asset names are matched without surrounding spaces and without case distinctions across manual
creation, renaming, and scan ingestion. To inspect collisions left by earlier versions, run:

```bash
docker compose exec backend python -m app.cli check-asset-names
```

Resolve collisions explicitly by renaming assets by ID; histories are never merged automatically.
Uploads with an ambiguous name return HTTP 409; use `asset_id` while resolving the names.
Expired password-reset credentials are cleaned up even when history retention is disabled. The
worker drains the backlog in transactions of at most 1,000 reset records; an explicit `prune`
command removes one batch and supports `--dry-run`.

For disconnected installations, disable feed synchronization and advisory lookups as needed. The CLI supports importing KEV and EPSS files downloaded elsewhere:

```bash
docker compose exec backend python -m app.cli --help
```

## Production

The production override requires Docker Compose 2.24.4 or later. It removes the published database port, binds the web service to loopback, and adds restart policies and bounded logs. Terminate HTTPS at a reverse proxy; an example is provided in [ops/Caddyfile](ops/Caddyfile).

The operations helper requires Python 3 and Docker; encrypted backups also use OpenSSL.

```bash
python3 scripts/production.py --env-file .env.production init-env
```

This creates a protected configuration file with generated secrets, administrator MFA enforcement, and metrics enabled. Before deployment, edit it to set:

- `PUBLIC_URL` to the public HTTPS URL and `GUARDIANO_ADMIN_EMAIL` to the administrator's address.
- `REAL_IP_FROM` to the trusted proxy CIDR.
- `POSTGRES_IMAGE`, `BACKEND_IMAGE`, and `FRONTEND_IMAGE` to tested image references pinned with `@sha256:…`.

GitHub Releases provide the tested Linux AMD64 images in `production-images.tar.gz`.
Download the archive and its checksum from the same release, then run:

```bash
sha256sum -c production-images.tar.gz.sha256
docker load -i production-images.tar.gz
```

For a digest-pinned production deployment, tag and push the loaded images
(`guardiano/backend:latest`, `guardiano/frontend:latest`, and `guardiano/db:latest`)
to your deployment registry. Use the digests reported by `docker push` in
`.env.production`.

Then validate and deploy:

```bash
python3 scripts/production.py --env-file .env.production preflight
python3 scripts/production.py --env-file .env.production deploy
```

The backend applies database migrations before serving traffic. Back up before upgrades. See [scripts/production.py](scripts/production.py) for deployment, encrypted backup, restore verification, and smoke-check commands; run it with `--help` for usage. [scripts/backup.sh](scripts/backup.sh) adds off-host backup upload through rclone. Example systemd units and monitoring configuration live under [ops](ops).

Prometheus metrics are optional and served at `/metrics` on the backend. The bundled frontend proxy does not expose that endpoint.

## Development

The stack uses React 19, TypeScript, and Vite for the frontend; FastAPI, SQLAlchemy, and Alembic for the backend; and PostgreSQL 16 for persistence. A separate worker handles queued jobs and periodic tasks.

For local tooling, use Python 3.12 or later, Node.js 24, and the pnpm version declared in [frontend/package.json](frontend/package.json).

### Backend

```bash
docker compose up -d db
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
export DATABASE_URL=postgresql+psycopg://guardiano:guardiano@localhost:5432/guardiano
python -m app.cli init-db
python -m app.cli create-admin admin@example.com
uvicorn app.main:app --reload --port 8000
```

For asynchronous features, run `python -m app.cli worker` in another terminal with the same environment. The root `.env` used by Compose is not automatically exported into your shell.

From `backend`, with the virtual environment active:

```bash
ruff check .
pytest --cov=app --cov-report=term-missing
```

Pure parser and deduplication checks can also run without PostgreSQL:

```bash
pytest -m no_database
```

Tests use a separate PostgreSQL database named `guardiano_test` by default and reset its schema. Set `TEST_DATABASE_URL` to select another dedicated test database. The database role must be able to create it if it does not already exist.

Alternatively, run backend tests in Docker from the repository root:

```bash
docker compose up -d db
docker compose build --build-arg INSTALL_DEV=true backend
docker compose run --rm --no-deps -v "$PWD/backend/tests:/app/tests:ro" backend test
```

### Frontend

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm dev
```

Vite proxies `/api` to `http://localhost:8000`; set `VITE_API_PROXY` to change the target.

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Browser and accessibility tests use Playwright via `pnpm test:browser`. See the [CI workflow](.github/workflows/ci.yml) for the PostgreSQL, Python environment, and Chromium setup.

### Dependency and API contracts

After changing Python dependencies, run these commands from `backend` using uv:

```bash
uv lock
uv export --locked --no-emit-project --no-dev --output-file requirements.lock
uv export --locked --no-emit-project --extra dev --output-file requirements-dev.lock
```

Commit all three lock files. For frontend dependency changes, commit `frontend/pnpm-lock.yaml`.

After changing the API schema, regenerate the OpenAPI document and TypeScript definitions from the repository root:

```bash
docker compose build backend
docker compose run --rm --no-deps --entrypoint python backend -m app.cli openapi - > frontend/src/api/openapi.json
(cd frontend && pnpm gen:api)
```

---

## Contributing 🤝

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog 📜

Detailed release history and version changes can be found in [CHANGELOG.md](CHANGELOG.md).

## Security 🔐

If you discover a security vulnerability, please see our [Security Policy](SECURITY.md).

## License 📝

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Author ✍️

[Salvatore Corvaglia](https://github.com/salvatorecorvaglia)
