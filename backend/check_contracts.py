"""Check API and dependency contracts; run from backend with the locked Python environment."""

import json
import re
import shutil
import subprocess
from pathlib import Path

from app.main import app

ROOT = Path(__file__).resolve().parent


def versions(path: Path) -> dict[str, str]:
    return dict(re.findall(r"^([\w.-]+)==([^\s\\]+)", path.read_text(), re.MULTILINE))


def main() -> None:
    # Compare complete exports (including hashes and markers) with the authoritative resolution.
    # The header records the command used to export, so it is not part of the dependency contract.
    def normalized(value: str) -> list[str]:
        return [
            line.strip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith("#")
        ]

    for name, options in (
        ("requirements.lock", ["--no-dev"]),
        ("requirements-dev.lock", ["--extra", "dev"]),
    ):
        expected = subprocess.run(  # noqa: S603, S607 -- fixed command and repository-owned arguments
            [
                shutil.which("uv") or "/usr/local/bin/uv",
                "export",
                "--locked",
                "--offline",
                "--no-cache",
                "--no-emit-project",
                *options,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if normalized(expected) != normalized((ROOT / name).read_text()):
            raise SystemExit(f"{name} differs from uv.lock; regenerate both dependency exports")
    runtime = versions(ROOT / "requirements.lock")
    development = versions(ROOT / "requirements-dev.lock")
    mismatches = {name for name, version in runtime.items() if development.get(name) != version}
    if mismatches:
        raise SystemExit(f"Runtime/dev dependency locks disagree: {sorted(mismatches)}")
    schema = ROOT.parent / "frontend/src/api/openapi.json"
    if json.loads(schema.read_text()) != app.openapi():
        raise SystemExit("OpenAPI changed: export app.openapi() and run pnpm gen:api")
    print("API schema and runtime/dev dependency contracts match")


if __name__ == "__main__":
    main()
