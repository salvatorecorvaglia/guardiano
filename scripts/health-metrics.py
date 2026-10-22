#!/usr/bin/env python3
"""Export Compose health for node_exporter's textfile collector; no secrets in output."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from production import compose


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', default='.env.production')
    parser.add_argument('--textfile-dir', required=True)
    args = parser.parse_args()
    result = subprocess.run(compose(args.env_file) + ['ps', '--all', '--format', 'json'],
                            check=True, capture_output=True, text=True)
    raw = result.stdout.strip()
    rows = json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines()]
    states = {row['Service']: row for row in rows}
    lines = []
    for service in ('db', 'backend', 'worker', 'frontend'):
        row = states.get(service, {})
        healthy = row.get('State') == 'running' and row.get('Health') == 'healthy'
        lines.append(f'guardiano_container_healthy{{service="{service}"}} {int(healthy)}\n')
    directory = Path(args.textfile_dir)
    fd, temp = tempfile.mkstemp(prefix='guardiano-health-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w') as output:
            output.writelines(lines)
        os.chmod(temp, 0o644)
        os.replace(temp, directory / 'guardiano-health.prom')
    finally:
        Path(temp).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
