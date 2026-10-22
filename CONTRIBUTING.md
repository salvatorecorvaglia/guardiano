# Contributing to Guardiano 💂‍♂️

Thanks for helping improve Guardiano. Bug reports, feature ideas, documentation fixes, and code contributions are welcome.

## Development setup

You need Docker with the Compose plugin. Copy the example configuration if you do not already have a `.env` file, then start the local stack from the repository root:

```bash
test -f .env || cp .env.example .env
docker compose up --build
```

The UI is available at <http://localhost:8080>, the API under `/api`, and the interactive API documentation at <http://localhost:8080/api/docs>. Rebuild the containers after changing the source code. See the [README](README.md#development) for more setup details. Keep secrets and local `.env` values out of contributions.

## Make a change

- Keep each pull request focused and explain the user-facing behavior it changes.
- Add or update tests for behavior changes. Update documentation when commands, configuration, or behavior change.
- Follow the existing Python style configured in [backend/pyproject.toml](backend/pyproject.toml) and the frontend style configured in [frontend/biome.json](frontend/biome.json).
- If you change the API schema, regenerate both the checked-in OpenAPI document and TypeScript definitions:

  ```bash
  docker compose run --rm --no-deps --entrypoint python backend -m app.cli openapi - > frontend/src/api/openapi.json
  (cd frontend && pnpm gen:api)
  ```

- If you change Python dependencies, regenerate `backend/requirements.lock` and `backend/requirements-dev.lock` using the `uv` commands in the [README](README.md#development). Commit the updated lock files. Commit `frontend/pnpm-lock.yaml` when frontend dependencies change.

## Check your work

Run the checks relevant to your change before submitting a pull request. Backend tests use PostgreSQL:

```bash
docker compose up -d db
docker compose build --build-arg INSTALL_DEV=true backend
docker compose run --rm --no-deps -v "$PWD/backend/tests:/app/tests:ro" backend test
```

For frontend changes, use Node.js 24 and pnpm:

```bash
cd frontend
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

For Python style checks, run `ruff check .` from `backend` with the development dependencies installed.

## Submit a pull request

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE/PULL_REQUEST_TEMPLATE.md). Describe the change, link any related issue, and list the checks you ran. Include screenshots for visible UI changes and call out any migration or configuration steps reviewers need to try the change. If a check could not be run, say why.

---

Happy coding! 💂‍♂️