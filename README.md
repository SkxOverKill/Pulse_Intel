# Pulse Intelligence

Open-source, self-hosted threat intelligence platform for analyst workflows.

Pulse Intelligence helps analysts and junior CTI teams track threat actors, campaigns,
indicators, vulnerabilities, ATT&CK techniques, automated feeds, enrichment results, hunts,
exports, and scheduled intelligence reports from one practical workspace.

## What It Does

- Track threat actors, aliases, campaigns, IOCs, reports, sources, CVEs, and ATT&CK mappings.
- Ingest public feeds from CISA KEV, NVD, FIRST EPSS, abuse.ch, OTX, vendor blogs, and security news.
- Enrich indicators with OTX, AbuseIPDB, and VirusTotal behind Redis-backed quota controls.
- Build saved threat hunts over indicator fields and alert on new matches.
- Export saved hunt matches for downstream blocking, reports, and tickets.
- Export filtered IOCs as CSV, STIX 2.1, MISP JSON, and Snort/Suricata rules.
- Expose scoped API keys for read-only programmatic access.
- Generate scheduled Markdown reports from new indicators, KEV additions, hunt alerts, and feed health.
- Review an admin-only audit log for authentication events, imports, exports, enrichment, and analyst actions.

## Status

Phases 1-7 of 8 are implemented. Phase 8 is hardening: large-table partitioning and
deeper security review.

See [`HISTORY.md`](HISTORY.md) for the development timeline and public-release cleanup notes.
See [`ROADMAP.md`](ROADMAP.md) for planned hardening and community work.

## Stack

| Area | Technology |
|---|---|
| App | Next.js 16.3 App Router, React 19.2, Turbopack |
| Data | PostgreSQL 17, Prisma 7, `@prisma/adapter-pg` |
| Jobs | BullMQ, Redis-compatible server |
| Auth | Argon2id passwords, DB-backed session cookies, hashed API keys |
| UI | Tailwind CSS v4, lucide-react |
| Tests | Vitest, TypeScript, ESLint |

## Quick Start

```bash
npm install
cp .env.example .env

# Fill DATABASE_URL, REDIS_URL, SESSION_SECRET, and any provider API keys.
# npm install runs prisma generate automatically; use npm run db:generate if needed.

npm run db:migrate
npm run db:seed
npm run db:seed:demo
npm run attack:sync -- --all
npm run feeds:install

npm run dev
```

Open `http://localhost:3000`.

Seed users:

| Email | Role |
|---|---|
| `admin@pulse.local` | ADMIN |
| `analyst@pulse.local` | ANALYST |
| `viewer@pulse.local` | READONLY |

Default password: `PulseAdmin!2026`

Set `SEED_PASSWORD` before `npm run db:seed` for anything beyond local development.

## Required Services

- Node.js 20.9+
- PostgreSQL 17 or compatible PostgreSQL
- Redis-compatible server for workers, enrichment queues, feed schedules, hunts, and reports

For Windows without Docker, native PostgreSQL plus Memurai works well. Docker Compose includes
Postgres and Redis services, but the app itself is currently intended to run as a Node process.

## Environment

Use `.env.example` as the template. Important values:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis-compatible connection string |
| `SESSION_SECRET` | Random 32+ byte session secret |
| `VIRUSTOTAL_API_KEY` | Optional enrichment provider |
| `ABUSEIPDB_API_KEY` / `ABUSEIPDB_API_KEYS` | Optional enrichment provider |
| `OTX_API_KEY` | Optional enrichment provider and OTX pulse feed |
| `NVD_API_KEY` | Recommended for reliable CVE sync |
| `PUBLIC_API_RATE_LIMIT_PER_WINDOW` | Optional public API limit, default `120` |
| `PUBLIC_API_RATE_LIMIT_WINDOW_SECONDS` | Optional public API window, default `60` |
| `SEED_PASSWORD` | Overrides local seed password |
| `PULSE_DEMO_MODE=1` | Public read-only demo mode using `viewer@pulse.local` |

Never commit `.env`, real provider keys, database dumps, or private investigation data.

## Worker

Run the worker beside the web app:

```bash
npm run worker
```

The worker owns feed refresh, enrichment queue draining, scheduled hunts, and scheduled reports.
Use `npm run worker -- --run-now` to run every enabled feed immediately on startup.

## Verification

```bash
npm run lint
npm run typecheck
npm run test
npm audit --audit-level=moderate
npm run build
```

Database-backed verification scripts:

```bash
npm run verify:enrichment -- --live
npm run verify:hunting
npm run verify:api
npm run verify:reports
```

## API

Create scoped API keys from `/settings`. See [`docs/API.md`](docs/API.md) for authentication,
rate limits, parameters, and examples.

Available read endpoints:

- `GET /api/health`
- `GET /api/health?deep=1`
- `GET /api/v1/indicators`
- `GET /api/v1/indicators/:id`
- `GET /api/v1/indicators?format=csv|stix|misp|snort`
- `GET /api/v1/actors`
- `GET /api/v1/actors/:id`

Whitelisted indicators are never returned by public API or export routes.
Public API responses include `X-RateLimit-*` headers, and exhausted keys receive `429`
with `Retry-After`.

## Deployment

Production needs two long-running processes:

```bash
npm run build
npm run start
npm run worker
```

Use a process manager such as `systemd`, `pm2`, or a platform supervisor. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) for host setup, Cloudflare tunnel notes, environment variables,
and migration guidance.

For database operations, see [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md).

## Design Rules

- Attribution is opinion: relation tables carry confidence and who added the claim.
- Whitelisting is load-bearing: whitelisted IOCs are stored for review but never exported,
  alerted on, matched by hunts, or enriched.
- Source decay is enforced: indicators inherit source half-life at ingest and expire out of
  working views, exports, and public API responses.
- Quotas are visible: bulk enrichment exposes real free-tier constraints instead of pretending
  large batches finish instantly.
- Report bodies render as text, not HTML, because reports contain attacker-controlled strings.
- ATT&CK imports are version-pinned and upgraded deliberately.

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md), open focused pull
requests, and include verification notes. Good first areas are feed parsers, API examples,
documentation, UI polish, and Phase 8 hardening.

Maintainer expectations are documented in [`MAINTAINERS.md`](MAINTAINERS.md). Program-review
context is available in [`docs/MAINTAINER_APPLICATION.md`](docs/MAINTAINER_APPLICATION.md).

Security issues should follow [`SECURITY.md`](SECURITY.md).
