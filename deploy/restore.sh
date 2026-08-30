#!/bin/sh
set -eu

if [ -z "${BACKUP_FILE:-}" ]; then
  echo "BACKUP_FILE must name a dump in ./backups" >&2
  exit 2
fi

case "$BACKUP_FILE" in
  */*|*..*)
    echo "BACKUP_FILE must be a file name, not a path" >&2
    exit 2
    ;;
esac

backup_path="/backups/$BACKUP_FILE"
if [ ! -f "$backup_path" ]; then
  echo "Backup not found: $backup_path" >&2
  exit 2
fi

pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error --dbname="$PGDATABASE" "$backup_path"
echo "Restore completed from $backup_path"
