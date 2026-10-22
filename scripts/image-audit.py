#!/usr/bin/env python3
"""Scan saved images without giving the scanner access to the Docker socket."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

# Official v0.76.1 multi-platform digest, verified at implementation time.
SCANNER = 'aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'


def evaluate(report):
    blocking, review = [], []
    for result in report['Results']:
        for finding in result.get('Vulnerabilities', []):
            if finding['Severity'] == 'CRITICAL' or (
                    finding['Severity'] == 'HIGH' and finding.get('FixedVersion')):
                blocking.append(finding)
            elif finding['Severity'] == 'HIGH':
                review.append(finding)
    return blocking, review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', action='append', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    blocked = False
    for index, image in enumerate(args.image):
        with tempfile.TemporaryDirectory(prefix='guardiano-image-audit-') as directory:
            archive = Path(directory) / 'image.tar'
            subprocess.run(['docker', 'save', '-o', str(archive), image], check=True)
            subprocess.run(['docker', 'run', '--rm', '-v', f'{directory}:/scan',
                            '-v', 'guardiano-trivy-cache:/root/.cache/', SCANNER, 'image',
                            '--input', '/scan/image.tar', '--scanners', 'vuln', '--format', 'json',
                            '--output', '/scan/report.json', '--no-progress'], check=True)
            raw = (Path(directory) / 'report.json').read_text()
            report = json.loads(raw)
            (output / f'image-{index}.json').write_text(raw)
            blocking, review = evaluate(report)
            print(f'{image}: {len(blocking)} blocking findings; '
                  f'{len(review)} high findings without fixes require pre-release risk review')
            for finding in blocking:
                print(f"  {finding['VulnerabilityID']} {finding['PkgName']} "
                      f"{finding['InstalledVersion']} -> {finding.get('FixedVersion', 'no fix')}")
            blocked |= bool(blocking)
    raise SystemExit(1 if blocked else 0)


if __name__ == '__main__':
    main()
