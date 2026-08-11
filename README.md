# Pulse Intelligence

Open-source, self-hosted Threat Intelligence Platform — APT actor tracking, campaigns, IOC management
with bulk enrichment, MITRE ATT&CK mapping, feed ingestion, threat hunting, and search.

Full plan and rationale: [`pulse_intelligence_spec.md`](pulse_intelligence_spec.md)

**Status: Phases 1–7 of 8 complete.** Foundation, auth, RBAC, audit log; CRUD for actors,
campaigns, indicators, reports and feeds; IOC bulk import; global search; MITRE ATT&CK v19.1
with matrix and technique mapping; enrichment (VirusTotal / AbuseIPDB / OTX) behind a Redis
rate limiter; 18 automated feeds; structured threat hunting; IOC exports; public API keys; and
scheduled reports.

Pulse Intelligence is built for analysts, junior intel analysts, SOC teams, students, and small
security teams who need a practical CTI workbench without buying a commercial platform first.

## Stack

| | |
|---|---|
| Framework | Next.js 16.2 (App Router, Turbopack, React 19.2) |
| Database | PostgreSQL + Prisma 7 (via `@prisma/adapter-pg`) |
| Styling | Tailwind v4 (CSS-first `@theme` tokens) |
| Auth | Argon2id + DB-backed session cookies |
| Queues | BullMQ + Redis |

## Running locally

```bash
npm install

# Terminal 1 — local Postgres (no Docker required)
npm run db:dev

# Terminal 2
npm run db:seed        # creates the three demo users
npm run db:seed:demo   # optional: 8 real APTs, 4 campaigns, sample IOCs
npm run dev
```

`db:seed:demo` loads publicly documented threat intel (APT29, Sandworm, Volt Typhoon…).
Its indicators are RFC 5737 / RFC 2606 documentation ranges, never real attacker
infrastructure — seeding a database with live IOCs that later get exported to a firewall is
a genuinely bad idea.

Open http://localhost:3000.

`npm run db:dev` prints a `DATABASE_URL` with a machine-specific port. If it differs from
what's in `.env`, update `.env` to match.

### Demo users

| Email | Role |
|---|---|
| `admin@pulse.local` | ADMIN |
| `analyst@pulse.local` | ANALYST |
| `viewer@pulse.local` | READONLY |

Password for all three: `PulseAdmin!2026` (override with `SEED_PASSWORD`).
**Development defaults only — change them before this is reachable by anyone else.**

## Scripts

| Script | Purpose |
|---|---|
| `npm run dev` | Next dev server |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run db:dev` | Local Prisma Postgres dev server |
| `npm run db:seed` | Seed demo users |
| `npm run db:studio` | Prisma Studio |
| `npm run db:migrate` | Standard `prisma migrate dev` (real Postgres only) |
| `npm run db:migrate:offline -- <name>` | Migration workaround for the dev server — see below |
| `npm run attack:sync` | Pull MITRE ATT&CK (enterprise; `--all` for every domain) |
| `npm run verify:hunting` | Verify scheduled hunt matching and alert behavior |
| `npm run verify:api` | Verify public API auth, scopes, and whitelist handling |
| `npm run verify:reports` | Verify scheduled report generation |

## Automation (feeds + enrichment)

```bash
npm run feeds:install          # install the 18-source catalogue (idempotent)
npm run worker                 # run feeds on schedule + drain the enrichment queue
npm run worker -- --run-now    # ...and run every feed immediately on boot
npm run verify:enrichment -- --live   # prove the rate limiter and API keys work
```

The worker must be running for anything automated to happen. It owns the hourly schedule,
re-reads it every 5 minutes so UI edits take effect without a restart, and removes
schedulers for feeds you disable.

**Sources** (all free): CISA KEV, NVD, FIRST EPSS, abuse.ch (URLhaus / ThreatFox / Feodo),
OTX pulses, and eleven vendor and government news feeds (CISA, Mandiant, Microsoft, Talos,
Unit 42, DFIR Report, Securelist, Krebs, SANS ISC, BleepingComputer, The Hacker News).

**Enrichment quotas** are the binding constraint, not queue throughput:

| Provider | Free tier | Cache TTL | Tried |
|---|---|---|---|
| AlienVault OTX | effectively unlimited | 72 h | first |
| AbuseIPDB | 1,000/day | 24 h | second |
| VirusTotal | **4/min, 500/day** | 168 h | last |

Ordering is deliberate: every indicator OTX can answer is a VirusTotal request preserved.
At 500/day, enriching 10,000 indicators against VirusTotal takes about 20 days — the
`/enrichment` page quotes real ETAs rather than implying "soon".

## MITRE ATT&CK

```bash
npm run attack:sync              # enterprise, pinned to v19.1
npm run attack:sync -- --all     # enterprise + mobile + ICS (~58 MB download)
```

The version is pinned in `src/lib/attack/stix.ts`. Upgrading is deliberate: MITRE reshapes
fields between releases — v19 moved detection off the technique object entirely — and
mappings should never shift because a scheduled job ran.

`--no-groups` skips importing MITRE's own group→technique attribution. Those imports are
recorded with no `addedById`, so the UI shows them as claimed by "MITRE ATT&CK" rather than
by an analyst.

**Migration drift warning.** `prisma migrate diff` emits `DROP INDEX` for all 13 raw-SQL
search indexes on every run, because they don't exist in `schema.prisma`. Applying that
silently turns every fuzzy and full-text search into a sequential scan.
`scripts/migrate-offline.ts` refuses to apply such a migration and prints the SQL for you
to hand-edit. If you switch to `prisma migrate dev`, you must check for this yourself.

## Two environment gotchas

**1. `prisma migrate dev` does not work against `npm run db:dev`.**
The local Prisma Postgres dev server doesn't implement the schema-engine RPCs that
`migrate dev` needs; it fails with `P1017` / "unexpected message from server". Everything
else (queries, `db execute`, introspection, Prisma Studio) works fine.

Use `npm run db:migrate:offline -- <name>` instead. It diffs, writes a real migration file,
applies it, and records it in `_prisma_migrations` — same end state, different route. Once
you move to a normal Postgres, use `npm run db:migrate` and delete
`scripts/migrate-offline.ts`.

**2. Docker and WSL2 are currently unavailable on this machine.**
`hypervisorlaunchtype` is `Off` in the boot config. To enable, in an **Administrator**
PowerShell, then reboot:

```powershell
bcdedit /set hypervisorlaunchtype auto
```

This is only needed for Redis (Phase 4+) and the Docker Compose deployment path. Phases 1–3
run entirely on `npm run db:dev`.

## Architecture notes

- **`src/proxy.ts`** — renamed from `middleware.ts` in Next 16. Deliberately only checks
  whether a session cookie exists; Next's guidance is that proxy must not rely on shared
  modules, so it never touches the database.
- **`src/lib/auth/dal.ts`** — the real auth gate. `requireUser()` / `requireRole()` verify
  the session against Postgres on every protected render, wrapped in React `cache()` so
  repeated calls in one pass cost a single query.
- **Session tokens** are stored only as SHA-256 hashes. A database dump yields no usable
  sessions.
- **Every relation carries `confidence` + `addedById`.** Attribution is opinion, not fact,
  and the UI must always be able to show who claimed what.
- **`Indicator` has a unique index on `(type, normalizedValue)`.** Feeds overlap heavily;
  dedup at ingest is what keeps the table meaningful.
- **`src/lib/ioc/*` is deliberately not marked `server-only`.** The Phase 4/5 worker is a
  plain Node process that shares `src/lib`, and `server-only` throws on import outside a
  bundler. It is still server-side in practice — it imports the Prisma client.
- **All ingest goes through `src/lib/ioc/ingest.ts`.** Bulk paste, report extraction, feeds
  and the API share one path, so dedup, whitelisting and confidence apply identically.
- **Report bodies render as preformatted text, not HTML** — they contain attacker-controlled
  strings, so a markdown-to-HTML renderer would be an XSS sink.

## Known issues

**The local Prisma dev Postgres is not robust enough for this workload — replace it.**
During a full feed ingest (1,651 KEV CVEs, ~2,000 IOCs, 350k EPSS rows parsed) the
`prisma dev` server wedged: ports stayed open but every connection was refused, and it
needed a kill plus a stale-lock cleanup at
`%LOCALAPPDATA%\prisma-dev-nodejs\Data\durable-streams\pulse\server.lock*` to recover.
No data was lost, but this will recur under hourly automation.

It also cannot handle: `prisma migrate dev` (P1017), introspection (`prepared statement
"s3" already exists`), or dynamically-shaped `upsert` calls (`08P01 bind message supplies
N parameters`). Those are worked around, but they are all symptoms of the same thing — it
is a development toy being asked to do production-shaped work.

**Fix:** install a real PostgreSQL. Native Windows works fine and needs no virtualization
(so the hypervisor being off does not matter):

```powershell
winget install PostgreSQL.PostgreSQL.17
```

Then set `DATABASE_URL` to it, run `npm run db:migrate` (the offline workaround becomes
unnecessary), and delete `scripts/migrate-offline.ts`.

**Queries are deliberately sequential in several places** (`getCounts` on the dashboard,
the enrichment page) rather than `Promise.all`, because concurrency against the dev server
triggers the failure above. Once on a real Postgres, those can go back to parallel.

`npm audit` reports a moderate PostCSS advisory (XSS via unescaped `</style>` in CSS
stringify output), reached transitively through `next`. It is build-time only and not
reachable at runtime here. Resolving it requires a breaking `npm audit fix --force`;
revisit when Next ships an updated PostCSS.
