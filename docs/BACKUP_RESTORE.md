# Backup And Restore

Pulse Intelligence stores operational CTI, API key **hashes**, users, sessions, audit logs, and
analyst-authored reports in PostgreSQL. A dump is therefore a sensitive intelligence artifact:
treat it like a production credential store, not a log file.

This document is the operator workflow for the `db:backup` / `db:restore` scripts. It covers a
safe default path — scheduled, rotated, encrypted, offsite — and a restore runbook.

## What the scripts do

- `npm run db:backup` — `pg_dump` custom format, with ownership/ACL metadata stripped so the
  dump restores across hosts. Supports `--retain`, `--verify`, `--encrypt` (below).
- `npm run db:restore` — `pg_restore --clean --if-exists`; **destructive**. Refuses to run
  without `--yes` and validates the dump *before* touching the target database.
- `npm run db:verify-backup` — non-destructive round-trip smoke test. Dumps `DATABASE_URL`,
  restores into a throwaway scratch database on the same server, diffs schema-only and
  data-only dumps of source vs restored, then drops the scratch database. Fails loudly on
  any mismatch. The CI `docker` job runs it against the compose stack on every PR, so a
  platform/image that silently breaks `pg_dump`/`pg_restore` fails CI instead of a restore.

## Requirements

- `pg_dump`, `pg_restore` **and `psql`** (PostgreSQL client tools) installed on the host.
- `DATABASE_URL` pointing at the database to back up or restore.
- The role in `DATABASE_URL` must have `CREATEDB` privilege (the smoke test creates and
  drops its own scratch database; the source database is only ever read).
- `openssl` only when using `--encrypt`.
- Enough encrypted storage for the exported dump.

## Creating backups

```bash
npm run db:backup
```

Writes `backups/pulse-intelligence-<timestamp>.dump`. Options:

| Flag | Meaning | Default |
| --- | --- | --- |
| `--dir <path>` | backup directory (also where rotation looks) | `backups` |
| `--output <path>` | explicit output file | timestamped name in `--dir` |
| `--retain <n>` | keep the newest `n` timestamped backups, prune the rest | `7` |
| `--verify` | smoke-test the dump with `pg_restore --list` before trusting it | off |
| `--encrypt` | AES-256-CBC encrypt (OpenSSL PBKDF2) to `<output>.dump.enc` | off |

Encryption example (passphrase read from the environment so it never appears in `ps`/argv):

```bash
export BACKUP_PASSPHRASE="$(openssl rand -base64 32)"
npm run db:backup -- --encrypt --verify
```

Only the ciphertext is left on disk; the plaintext dump is deleted after encryption.

### Scheduled, rotated workflow

Run daily from cron (or a systemd timer / your container scheduler). The scripts exit
non-zero on failure, so a failed run surfaces in cron mail / alerting:

```cron
10 2 * * *  cd /opt/pulse-intel && BACKUP_PASSPHRASE_FILE=$(cat /run/secrets/pulse-backup-passphrase) \
             BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE_FILE" npm run db:backup -- --encrypt --verify --retain 7
```

Then copy the newest `*.dump.enc` offsite (object storage, another host, an immutable
bucket). Keep the passphrase out of the backup storage: a dump with its key is not a backup.

Retention tip: the dump contains everything, so "keep 7 daily" plus a weekly offsite copy
covers most self-hosted deployments; scale to your own retention policy.

## Restoring

Restores are destructive — `pg_restore --clean` drops existing objects. The script refuses
to run without `--yes` for exactly that reason.

### Runbook

1. **Stop the app and worker** so feed jobs and API writes do not race the restore.
   (`docker compose stop` if you run the compose stack.)
2. **Confirm `DATABASE_URL`** points at the intended target host/database — one typo here
   is how you restore a prod dump over staging.
3. **Take a fresh backup of the target** if it contains anything you might want.
4. Restore:
   ```bash
   npm run db:restore -- --input backups/pulse-intelligence-2026-08-11T02-10-00-000Z.dump.enc --yes
   ```
   `.enc` inputs are decrypted to a temp file that is deleted as soon as the restore
   finishes — even on failure.
5. **Verify** before resuming traffic:
   - `npm run db:generate` if this is part of a deployment rebuild (schema matches the
     client), then apply any migrations that postdate the dump (`npm run db:migrate`).
   - Restart app and worker.
   - Check `/api/health`, then spot-check real data: a known indicator, a source's
     `lastRunAt` on the feeds page, and the audit log.
6. **Expect a re-sync**, not instant freshness: feeds only write on their next scheduled
   run, and expiry/prune jobs will trim data older than their windows.

### Why the workflow is shaped this way

- `--no-owner --no-acl` makes dumps portable between hosts and lets restore run as any role
  with database rights.
- The preflight `pg_restore --list` turns "restore silently half-imported a corrupt dump"
  into "refused before touching anything".
- `--retain` in the script, not in a wrapper, means rotation cannot be forgotten when the
  cron line is copied to a new host.

## Security notes

- **Dumps are classified data.** They contain operational intelligence, user records,
  session state, audit logs, and API key hashes (keys themselves are stored hashed and are
  never exported by the API — but the dump still proves who has access to what).
- **Encrypt at rest** (`--encrypt`, or your own age/gpg tooling). Never write plaintext
  dumps to shared or synced storage. If you use managed object storage, use server-side
  encryption *and* keep the passphrase elsewhere.
- **The passphrase is a secret**: store it in your secret manager, rotate it on staff
  changes, and remember that old dumps stay decryptable only by the passphrase that
  encrypted them — re-encrypt on rotation if you need continuity.
- **Secrets never live in the dump.** `DATABASE_URL` and `AUTH_SECRET` come from the
  environment, not PostgreSQL, so a leaked dump does not leak the session-signing key or
  DB credentials. Keep `AUTH_SECRET` stable across restores or user sessions invalidate.
- **Access control**: anyone who can read dumps or the passphrase can read your intelligence.
  Limit both to the operators who already have production database access.
- **Restore target hygiene**: restoring a production dump into a lower environment is still
  a production-data exposure. Use redacted/scrubbed data where possible; if you must, treat
  the lower environment with production sensitivity afterwards.
- **Managed Postgres alternative**: on RDS/Aurora/Cloud SQL, automated snapshots and
  point-in-time recovery cover the same need with less operator tooling. The `db:backup`
  path remains the portable, vendor-neutral option and your fallback when you need a dump
  to move hosts.
- **Disaster recovery test**: restore into a throwaway database on a schedule (quarterly is
  a common cadence). A backup that has never been restored is a wish, not a backup. The
  one-liner version of that test is `npm run db:verify-backup` — run it on the box that
  holds the platform (or in a non-production container pointed at a copy host) after any
  platform/Postgres upgrade, and whenever the CI stack changes images.

## Storage guidance

- Keep backups outside the Git repository (the `backups/` dir is gitignored; verify yours
  is too).
- Encrypt backups at rest, limit access, and rotate per your deployment's sensitivity
  policy — a dump from 90 days ago is still your full indicator history.
