# Guardiano 💂‍♂️

**Self-hosted application vulnerability management platform**

**Guardiano** is a self-hosted application vulnerability management platform. It centralizes security scanner output into one searchable, triageable inventory.

## What it provides

- A searchable inventory of findings, assets, vulnerabilities, and software components
- SAST, SCA, IaC, and DAST report ingestion with cross-scan deduplication
- Finding ownership, comments, tags, due dates, severity overrides, and full history
- Configurable remediation SLAs, triage rules, saved views, and quality gates
- Preview scans for branches and pull requests without changing the main inventory
- Risk acceptance workflows, including expiry and optional four-eyes approval
- CISA KEV and EPSS enrichment, license policies, VEX, and SBOM export
- Jira, GitHub, and GitLab issue tracking; webhooks, email notifications, and scheduled reports
- Role-based access, teams, scoped API tokens, MFA, OIDC single sign-on, and audit logging
- Dashboards, trend reports, CSV/JSON exports, and optional Prometheus metrics

## Supported report formats

Guardiano detects these formats automatically:

| Category | Formats |
| --- | --- |
| Standard | SARIF 2.1.0, CycloneDX JSON |
| SAST and secrets | Semgrep JSON, Gitleaks JSON, Guardiano JSON |
| SCA | Trivy JSON, Grype JSON, OSV-Scanner JSON, OWASP Dependency-Check JSON, `npm audit` JSON |
| IaC | Checkov JSON, KICS JSON, Trivy JSON |
| DAST | OWASP ZAP JSON, Nuclei JSON or JSON Lines |

SARIF also makes Guardiano compatible with scanners such as CodeQL and other tools that emit the
standard format.

## Quick start

You need Docker with the Compose plugin. From the repository root, create `.env` only if it does not
already exist:

```bash
test -f .env || cp .env.example .env
```

The values from `.env.example` are for local evaluation:

```text
admin@example.com
ChangeMe-Admin-2026!
```

At startup, Guardiano applies versioned Alembic database upgrades, including the PostgreSQL
`pg_trgm` extension. Existing unversioned 1.0 databases are adopted only after their schema is
verified; drift causes an explicit refusal. Run `python -m app.cli init-db` manually to upgrade,
and `python -m app.cli check-db` to check the revision. Read the
[production upgrade and regression gates](docs/production-readiness.md) before upgrading an existing installation.

Before starting a deployment reachable by other people, set unique `GUARDIANO_ADMIN_PASSWORD`,
`SECRET_KEY`, and `POSTGRES_PASSWORD` values in `.env`. Then start the stack:

```bash
docker compose up -d --build
```

Open <http://localhost:8080> and sign in with the administrator credentials in `.env`. On first
startup, Guardiano creates the database schema and the initial administrator automatically.

To populate a local installation with sample users, assets, findings, and scan history:

```bash
docker compose exec backend python -m app.cli seed-demo
```

The seeded accounts are `admin@guardiano.local`, `manager@guardiano.local`,
`analyst@guardiano.local`, and `viewer@guardiano.local`. Their development-only password is
`Guardiano-Demo-2026!`.

## Upload a scan

Create an API token with the `ingest` scope under **Settings → Account & API tokens**, then upload a report:

```bash
export GUARDIANO_URL=http://localhost:8080
export GUARDIANO_TOKEN='your-token'

curl --fail-with-body -X POST "$GUARDIANO_URL/api/v1/scans" \
  -H "Authorization: Bearer $GUARDIANO_TOKEN" \
  -F "file=@backend/tests/fixtures/reports/semgrep.sarif" \
  -F "asset_name=my-service" \
  -F "branch=main" \
  -F "close_missing=true"
```

The file in this example is a bundled test fixture. Replace it with a report produced by your scanner.
You can also send `commit_sha` when you have a Git commit to associate with the scan.

`asset_name` creates the asset when it does not exist. `close_missing=true` resolves active findings
from the same scanner that disappeared from a complete default-branch scan. If an asset has a default
branch and the uploaded `branch` differs, Guardiano treats the upload as a preview: its quality gate
is evaluated, but the inventory is unchanged.

In development, interactive API documentation is available at
<http://localhost:8080/api/docs>.

## Development

Start the local stack:

```bash
docker compose up --build
```

The UI is served at <http://localhost:8080>, with the API under `/api` and API docs at
<http://localhost:8080/api/docs>. Rebuild the containers after changing the source code.

Run the backend tests against PostgreSQL:

```bash
docker compose up -d db
docker compose build --build-arg INSTALL_DEV=true backend
docker compose run --rm --no-deps -v "$PWD/backend/tests:/app/tests:ro" backend test
```

Run the frontend checks with Node.js 24 and pnpm:

```bash
(
  cd frontend
  pnpm install
  pnpm lint
  pnpm typecheck
  pnpm test        # frontend unit tests
  pnpm build       # production frontend build
)
```

Generate both hashed Python dependency exports from the same resolution:

```bash
cd backend
uv lock
uv export --no-dev --no-emit-project --format requirements-txt -o requirements.lock
uv export --extra dev --no-emit-project --format requirements-txt -o requirements-dev.lock
python check_contracts.py
```

When the API schema changes, regenerate the checked-in OpenAPI document and TypeScript definitions:

```bash
docker compose run --rm --no-deps --entrypoint python backend -m app.cli openapi - > frontend/src/api/openapi.json
(cd frontend && pnpm gen:api)
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 Changelog

Detailed release history and version changes can be found in [CHANGELOG.md](CHANGELOG.md).

## 🔐 Security

If you discover a security vulnerability, please see our [Security Policy](SECURITY.md).

## 📝 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

**Author**: [Salvatore Corvaglia](https://github.com/salvatorecorvaglia)