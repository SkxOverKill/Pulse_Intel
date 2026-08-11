# Backup And Restore

Pulse Intelligence stores operational CTI, API key hashes, users, sessions, audit logs, and
analyst-authored reports in PostgreSQL. Treat backups as sensitive intelligence artifacts.

## Requirements

- `pg_dump` and `pg_restore` installed on the host.
- `DATABASE_URL` set to the PostgreSQL database you want to back up or restore.
- Enough encrypted storage for the exported dump.

## Create A Backup

```bash
npm run db:backup
```

By default, backups are written to `backups/pulse-intelligence-<timestamp>.dump`.

Custom path:

```bash
npm run db:backup -- --output C:\secure-backups\pulse-2026-08-11.dump
```

The backup uses PostgreSQL custom format with ownership and ACL metadata removed, which makes
restoring across hosts easier.

## Restore A Backup

Restores are destructive because they use `pg_restore --clean --if-exists`.

```bash
npm run db:restore -- --input backups/pulse-intelligence-2026-08-11.dump --yes
```

Before restoring:

- Confirm `DATABASE_URL` points at the intended target.
- Stop the worker process so feed jobs do not write during restore.
- Take a fresh backup of the target database if it contains useful data.
- Restart the app and worker after restore.
- Run `npm run db:generate` if the restore is part of a deployment rebuild.

## Storage Guidance

- Keep backups outside the Git repository.
- Encrypt backups at rest.
- Limit access to maintainers/operators who already have production database access.
- Rotate backups according to the sensitivity and retention policy of your deployment.
