# Pulse Intelligence

Self-hosted Threat Intelligence Platform — APT actor tracking, campaigns, IOC management
with bulk enrichment, MITRE ATT&CK mapping, feed ingestion, threat hunting, and search.

Full plan and rationale: [`../pulse_intelligence_spec.md`](../pulse_intelligence_spec.md)

**Status: Phases 1–2 of 8 complete.** Foundation, auth, RBAC, audit log, schema and app
shell; plus CRUD for actors, campaigns, indicators, reports and feeds, IOC bulk import, and
global search.

## Stack

| | |
|---|---|
| Framework | Next.js 16.2 (App Router, Turbopack, React 19.2) |
| Database | PostgreSQL + Prisma 7 (via `@prisma/adapter-pg`) |
| Styling | Tailwind v4 (CSS-first `@theme` tokens) |
| Auth | Argon2id + DB-backed session cookies |
| Queues | BullMQ + Redis *(Phase 4)* |

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
**Development defaults — change them before this is reachable by anyone else.**

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

**Intermittent `P1017 / ConnectionClosed` in the dev log.** Appears when a `next build` or
seed script runs against the local dev Postgres at the same time as `next dev` — several
Prisma pools against one small server. Not reproducible from an idle connection alone
(tested to a 60s gap, with and without idle expiry), and not seen against a normal Postgres.
Requests still return 200 in steady state. Unresolved; see the comment in `src/lib/db.ts`
and do not assume the pool config there fixed it.

`npm audit` reports a moderate PostCSS advisory (XSS via unescaped `</style>` in CSS
stringify output), reached transitively through `next`. It is build-time only and not
reachable at runtime here. Resolving it requires a breaking `npm audit fix --force`;
revisit when Next ships an updated PostCSS.
