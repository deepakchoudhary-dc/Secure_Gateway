#!/bin/sh
set -eu

mkdir -p /backups
backup_file="/backups/ai_security_$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --no-owner --no-privileges --file="$backup_file"
echo "Backup written to $backup_file"
