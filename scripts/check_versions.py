"""Check manifest versions, optionally against a release tag."""
import argparse
import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--tag", help="Release ref, including refs/tags/v prefix")
args = parser.parse_args()

module = ast.parse((ROOT / "backend/app/__init__.py").read_text())
backend = next(
    ast.literal_eval(node.value)
    for node in module.body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
)
versions = {
    "backend": backend,
    "frontend": json.loads((ROOT / "frontend/package.json").read_text())["version"],
}
if (
    any(not isinstance(value, str) or not value for value in versions.values())
    or len(set(versions.values())) != 1
):
    raise SystemExit(f"Version mismatch: {versions}")
version = next(iter(versions.values()))
if args.tag is not None:
    if not args.tag.startswith("refs/tags/v") or args.tag != f"refs/tags/v{version}":
        raise SystemExit(f"Release ref {args.tag!r} must match refs/tags/v{version}")
    if not re.fullmatch(
        r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
        args.tag.removeprefix("refs/tags/"),
    ):
        raise SystemExit("Release tags must use vMAJOR.MINOR.PATCH")
print(f"Versions agree: {version}")
