# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add controlled Compose image updates with health checks, a persistent image journal, and recovery to previous images.
- Require encrypted backup and restore verification before updates; stop writes when schema changes prevent safe image rollback.

### Fixed

- Updated the frontend runtime's curl and libcurl packages for CVE-2026-92392.
- CI tears down the container job cleanly when it fails before the disposable
  production environment is created.

### Changed

- Update frontend dependencies and Biome to `2.6.3`.
- Refresh the project logo and README.

## [1.1.0] - 2026-10-24

### Added

- Production operations helper for generating configuration with secure defaults,
  validating deployment settings and pinned image digests, deploying, and running
  smoke checks.
- Encrypted database backups, restore drills with optional application checks,
  off-host backup uploads through rclone, and systemd backup scheduling.
- Health metrics collection, systemd health checks, Prometheus monitoring and alert
  examples, and a Caddy HTTPS reverse proxy example.
- CI audits for production dependencies and container images, plus production
  startup, MFA, report ingestion, and encrypted restore checks.
- Release publishing of the container images verified by CI to GitHub Container
  Registry, with image digests attached as `release-images.env`.
- Reproducible SQL-plan, connection-pool queue-wait and maximum-upload HTTP
  memory probes under `backend/benchmarks`.

### Changed

- Ingestion locks only matching, fingerprint and scanner-resolution candidates;
  persistence flushes bounded batches within one atomic transaction.
- Automatic ticket candidate selection and KEV matching run in SQL, with bounded
  job creation that preserves the shared per-scan ticket limit.
- Analytics intersects status and severity intervals to reduce history-query sorts.
- Backend images use a digest-pinned Alpine runtime to eliminate the previously
  reported Debian high-severity vulnerabilities.
- Enforcing SSO now rejects existing local sessions as well as password sign-ins.
- Integration destinations with linked tickets or pending work must be replaced
  by a new integration; credentials and operational settings remain editable.
- SLA cache refreshes reuse request connections, and report rankings and triage
  matching apply their filters consistently before limiting results.
- Hardened the production Compose configuration with required secrets, explicit
  environment files, bounded container logs, and init processes.
- Added a dedicated PostgreSQL runtime image alongside the backend and frontend
  images.
- Expanded the README with report format identifiers, API upload behavior,
  configuration guidance, production operations, and local development workflows.

### Fixed

- Full-size uploads now pass the frontend proxy with multipart metadata; oversized
  report files remain rejected by the backend.
- Updated the frontend runtime's Brotli library for CVE-2026-111497.
- Indexed SARIF artifact locations no longer collapse distinct findings, and
  complete combined reports remove obsolete scanner attribution.
- MFA management now enforces persistent per-account attempt limits.
- Ticket creation rechecks integration availability and destination changes;
  automatic tickets and SCM feedback respect integration asset restrictions.
- Concurrent product and gate creation, large JSON integers, and disabled manual
  report sends return consistent results instead of errors or false success.
- Asset, finding, scan and gate-policy pages reset local state when their resource
  changes, and gate-policy fields are disabled while saving or deleting.
- Desktop resizing releases mobile focus restrictions, and notifications expose
  failures and retry actions.
- Finding history includes severity transitions, and CI examples use the maintained
  action with explicit pull-request previews and quality-gate enforcement.

## [1.0.0] - 2026-10-22

### Added

- First implementation of Guardiano.
