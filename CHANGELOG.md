# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- Hardened the production Compose configuration with required secrets, explicit
  environment files, bounded container logs, and init processes.
- Added a dedicated PostgreSQL runtime image alongside the backend and frontend
  images.
- Expanded the README with report format identifiers, API upload behavior,
  configuration guidance, production operations, and local development workflows.

## [1.0.0] - 2026-10-22

### Added

- First implementation of Guardiano.
