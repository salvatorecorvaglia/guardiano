#!/bin/sh
# Run as a dedicated operator with Docker access. Fail before marking success if upload fails.
set -eu
: "${BACKUP_KEY_FILE:?Set BACKUP_KEY_FILE to a protected random key file}"
: "${BACKUP_REMOTE:?Set BACKUP_REMOTE to an rclone remote outside this host}"
: "${TEXTFILE_DIR:?Set TEXTFILE_DIR to node_exporter textfile collector directory}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BACKUP_DIR=${BACKUP_DIR:-/var/backups/guardiano}
ENV_FILE=${ENV_FILE:-$ROOT/.env.production}
umask 077
mkdir -p "$BACKUP_DIR"
ARCHIVE="$BACKUP_DIR/guardiano-$(date -u +%Y%m%dT%H%M%SZ).dump.enc"
python3 "$ROOT/scripts/production.py" --env-file "$ENV_FILE" backup "$ARCHIVE" --key-file "$BACKUP_KEY_FILE"
rclone copyto "$ARCHIVE" "$BACKUP_REMOTE/$(basename "$ARCHIVE")"
rclone copyto "$ARCHIVE.json" "$BACKUP_REMOTE/$(basename "$ARCHIVE").json"
# This metric means both encrypted files were uploaded successfully.
printf 'guardiano_backup_last_success_unixtime %s\n' "$(date +%s)" > "$TEXTFILE_DIR/guardiano-backup.prom.tmp"
chmod 644 "$TEXTFILE_DIR/guardiano-backup.prom.tmp"
mv "$TEXTFILE_DIR/guardiano-backup.prom.tmp" "$TEXTFILE_DIR/guardiano-backup.prom"
# Expire only completed local backups after successful off-host upload.
python3 - "$BACKUP_DIR" "${BACKUP_RETENTION_DAYS:-30}" <<'PYTHON'
import sys, time
from pathlib import Path
root, days = Path(sys.argv[1]), int(sys.argv[2])
if days < 1:
    raise SystemExit('BACKUP_RETENTION_DAYS must be positive')
cutoff = time.time() - days * 86400
for archive in root.glob('guardiano-*.dump.enc'):
    metadata = Path(str(archive) + '.json')
    if archive.is_file() and metadata.is_file() and archive.stat().st_mtime < cutoff:
        archive.unlink()
        metadata.unlink()
PYTHON
