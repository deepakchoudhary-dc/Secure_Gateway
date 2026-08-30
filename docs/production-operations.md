# Production operations

## Database migrations

The production container refuses to start against an outdated schema. Apply migrations before rollout:

```sh
docker compose run --rm migrate
```

## Backup and restore

Create a one-off PostgreSQL custom-format backup in `./backups`:

```sh
docker compose --profile operations run --rm backup
```

Restore a selected dump. Restores are destructive and should be tested in an isolated environment first:

```sh
BACKUP_FILE=ai_security_YYYYMMDDTHHMMSSZ.dump docker compose --profile operations run --rm restore
```

Copy backups to encrypted off-site storage and apply an organization-approved retention policy outside the application host.

## Retention and erasure

`DATA_RETENTION_DAYS` defaults to 90. The existing outbox worker removes expired logs, completed HITL reviews, feedback, completed outbox events, idempotency records, and JWT revocations.

Administrators can erase tenant-scoped records with:

```text
DELETE /api/v1/admin/tenants/{tenant_id}/data
```

## Recovery check

Periodically restore the latest backup into an isolated Postgres instance, run `alembic upgrade head`, and verify `/ready` before considering the backup usable.
