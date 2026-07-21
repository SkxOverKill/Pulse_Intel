# Pulse Intelligence — Handover

Last updated: **2026-07-21**
Status: **Phases 1–5 of 8 complete.** 30 routes, 96 tests, clean build.

A self-hosted Threat Intelligence Platform — APT tracking, campaigns, IOC management with
bulk enrichment, MITRE ATT&CK, automated feed ingestion, and search.

- **Plan and rationale:** [`../pulse_intelligence_spec.md`](../pulse_intelligence_spec.md)
- **Setup and day-to-day commands:** [`README.md`](README.md)
- **This file:** how to pick the project up on another machine, and what not to break.

---

## 1. Moving to the RDP box — read this first

Two things will bite you, in this order.

### 1.1 The repo has no remote

`git remote -v` is empty. The code exists only in this folder. Pick one:

**Option A — push to a private GitHub repo (recommended).** Survives disk loss, and you
can pull from anywhere. Create an empty **private** repo on github.com first, then:

```bash
cd "C:\Users\Sukesh\Downloads\Pulse Development\pulse_intelligence"
git remote add origin https://github.com/<you>/pulse-intelligence.git
git push -u origin master
```

Then on the RDP box: `git clone https://github.com/<you>/pulse-intelligence.git`

(`gh` is not installed on the original machine — `winget install GitHub.cli` if you'd
rather use `gh repo create --private --source=.` instead of the web UI.)

Make sure the repo is **private**: the code is clean of secrets, but the feed catalogue
and design notes are your work.

**Option B — copy the folder.** Copy `pulse_intelligence\` including the `.git` directory
(700 KB — the whole history comes with it). Do **not** copy `node_modules` or `.next`;
run `npm install` on the other side instead.

### 1.2 Secrets do NOT travel with git

`.env` is gitignored — correctly, but it means a fresh clone has no API keys and no
database URL. **You must recreate `.env` on the RDP box by hand.** `.env.example` is
committed as the template; the real values are only in your local `.env`.

Copy it across out-of-band (password manager, not email/chat), or regenerate the keys.

> **Rotate the three API keys.** VirusTotal, AbuseIPDB and OTX keys were pasted into a
> chat transcript on 2026-07-21. Nothing is known to be compromised, but they have been
> seen by more than one system. Free-tier keys are trivial to regenerate:
> [VirusTotal](https://www.virustotal.com/gui/my-apikey) ·
> [AbuseIPDB](https://www.abuseipdb.com/account/api) ·
> [OTX](https://otx.alienvault.com/settings)

---

## 2. Bringing it up on a new machine

### 2.1 Prerequisites

| Requirement | Notes |
|---|---|
| **Node.js 20.9+** | Next.js 16 minimum. Developed on 25.8.1. |
| **PostgreSQL 17** | `winget install PostgreSQL.PostgreSQL.17` — native Windows, no virtualization needed. **See §4.1 before using `npm run db:dev` instead.** |
| **Redis-compatible server** | Memurai on the old box (`winget install Memurai.MemuraiDeveloper`). Needed for enrichment + scheduling. |
| Docker / WSL2 | **Not required.** The old machine had the hypervisor disabled and everything still worked. |

### 2.2 First run

```bash
npm install

# create .env from .env.example, fill in DATABASE_URL, REDIS_URL and the three API keys

npm run db:migrate          # real Postgres. (dev server: see §4.1)
npm run db:seed             # 3 users — admin/analyst/viewer @pulse.local
npm run db:seed:demo        # optional: 8 real APTs, 4 campaigns, sample IOCs
npm run attack:sync -- --all  # MITRE ATT&CK v19.1 (~58 MB download, ~1 min)
npm run feeds:install       # register the 18-source feed catalogue

# then, in two terminals:
npm run dev                 # http://localhost:3000
npm run worker -- --run-now # feeds + enrichment; --run-now pulls everything immediately
```

Sign in as `admin@pulse.local` / `PulseAdmin!2026`. **Change these before the app is
reachable by anyone else** (`SEED_PASSWORD` overrides the seed default).

### 2.3 Sanity checks

```bash
npm run test                          # 96 tests, all pure logic — no DB or network
npm run typecheck
npm run verify:enrichment -- --live   # proves the rate limiter + all three API keys
npm run build
```

`verify:enrichment` is the highest-value one: it fires 20 concurrent requests at a 4/min
quota and asserts exactly 4 are allowed. If that fails, Redis or the limiter is broken.

---

## 3. Where things are

```
prisma/schema.prisma           the data model — read this first
prisma/migrations/             hand-managed; see §4.2
src/
  proxy.ts                     renamed from middleware.ts in Next 16. Cookie check only.
  worker.ts                    background process: feeds, enrichment, scheduling
  lib/
    db.ts                      Prisma client (driver adapter — Prisma 7 requires one)
    redis.ts                   shared Redis + BullMQ connection factory
    auth/dal.ts                THE auth gate. requireUser / requireRole.
    actions.ts                 withAction() — RBAC + zod + error handling for mutations
    ioc/normalize.ts           refang, type detection, dedup normalization (43 tests)
    ioc/whitelist.ts           never-block list (9 tests)
    ioc/ingest.ts              the single ingest path for ALL indicator sources
    attack/stix.ts             ATT&CK STIX parsing (16 tests)
    attack/sync.ts             ATT&CK ingest
    enrichment/limiter.ts      Redis token bucket (the Lua script)
    enrichment/registry.ts     provider order — OTX first, VirusTotal last
    enrichment/providers/      virustotal, abuseipdb, otx, stub
    feeds/parsers.ts           RSS/CSV/KEV/EPSS/NVD parsing (20 tests)
    feeds/catalog.ts           the 18 preconfigured sources
    feeds/run.ts               feed execution + health tracking
    queue/queues.ts            BullMQ queues and priorities
  app/(app)/                   authenticated pages
  app/(auth)/                  login
scripts/                       CLI: attack-sync, install-feeds, verify-enrichment, migrate-offline
```

---

## 4. Known issues and traps

### 4.1 The `prisma dev` database is not production-capable

`npm run db:dev` starts a local Postgres with no Docker, which is why it was used. But
during a full feed ingest it **wedged** — ports stayed open, every connection refused —
and needed a process kill plus deleting
`%LOCALAPPDATA%\prisma-dev-nodejs\Data\durable-streams\pulse\server.lock*`.

It also cannot handle:
- `prisma migrate dev` → `P1017`
- introspection → `prepared statement "s3" already exists`
- dynamically-shaped Prisma `upsert` → `08P01 bind message supplies N parameters`
- concurrent queries → dropped connections

All are worked around in the code, but they are symptoms of one thing: it is a development
toy doing production-shaped work. **Install real PostgreSQL on the RDP box.** Then:

- use `npm run db:migrate` and delete `scripts/migrate-offline.ts`
- the sequential-query comments in `src/app/(app)/page.tsx` and `enrichment/page.tsx` no
  longer apply — those can go back to `Promise.all`

### 4.2 Migrations will try to delete your search indexes

**Every** `prisma migrate diff` emits `DROP INDEX` for the 13 pg_trgm/FTS indexes created
in `20260721010000_search_indexes`, because they are raw SQL and don't exist in
`schema.prisma`. Applying that silently turns fuzzy and full-text search into sequential
scans — no error, just slow.

`scripts/migrate-offline.ts` refuses such a migration and prints the SQL to hand-edit.
**If you switch to `prisma migrate dev`, you lose that guard** — check generated migrations
for `DROP INDEX` yourself, every time.

### 4.3 Smaller traps that cost time

- **BullMQ rejects `:`** in queue names *and* custom job ids. Use `-` or `__`.
- **`nulls: "last"` on every DESC sort over a nullable column.** Postgres defaults to
  NULLS FIRST, which put 1,571 unscored CVEs above 577 scored ones and made the dashboard
  claim an EPSS ranking it wasn't doing.
- **Regenerating the Prisma client needs a dev-server restart.** The client is cached on
  `globalThis` for HMR, so a new model reads as `undefined` until you restart.
- **`server-only` must NOT be added to `src/lib/ioc`, `src/lib/feeds`, `src/lib/attack` or
  `src/lib/enrichment`.** The worker is plain Node and imports them; `server-only` throws
  outside a bundler. It belongs only on request-scoped code (`auth/`, `audit.ts`).
- **vitest needs the `@/` alias** in `vitest.config.ts`. Type-only imports get erased and
  hide a missing alias until the first runtime import.
- Browser screenshots time out in this environment; verify UI via computed styles / DOM.

---

## 5. Design rules — please don't break these

These are load-bearing. Each exists because the alternative produces a platform that lies.

1. **Every relation carries `confidence` + `addedById`.** Attribution is opinion, not fact.
   The UI must always be able to answer "who claimed this, and how sure were they?".
   Imported MITRE mappings deliberately have no `addedById` so they display as
   "MITRE ATT&CK", not as an analyst's judgement.
2. **`Indicator` is unique on `(type, normalizedValue)`.** Feeds overlap heavily; dedup at
   ingest is the only thing keeping the table meaningful. All ingest goes through
   `src/lib/ioc/ingest.ts` so dedup, whitelisting and confidence apply identically.
3. **Whitelisting is never bypassed.** The `8.8.8.8`-in-a-C2-feed case is real. Whitelisted
   IOCs are stored (so you can see the feed claimed it) but never exported, alerted on, or
   enriched.
4. **Quota limits are surfaced, never hidden.** VirusTotal is 4/min and 500/day; a
   10k-indicator batch takes ~20 days and `/enrichment` says so. Never show a spinner that
   implies "soon".
5. **Provider order is OTX → AbuseIPDB → VirusTotal.** Cheapest first; every OTX answer is
   a VirusTotal request preserved.
6. **Report bodies render as preformatted text, not HTML.** They contain attacker-controlled
   strings; a markdown→HTML renderer would be an XSS sink.
7. **ATT&CK is version-pinned** in `src/lib/attack/stix.ts`. MITRE reshapes fields between
   releases (v19 moved detection off the technique object entirely). Upgrading is a
   deliberate act, never something a cron does.
8. **`proxy.ts` only checks for a cookie.** Real verification is in `lib/auth/dal.ts`, per
   Next's guidance that proxy must not rely on shared modules. Don't move auth into proxy.

---

## 6. Current data (as of handover)

Reproducible from scratch with the §2.2 commands.

| | |
|---|---|
| Threat actors | 8 real APTs, 30 cross-vendor aliases |
| ATT&CK | 943 techniques, 41 tactics (v19.1), 634 MITRE group mappings |
| Vulnerabilities | 2,148 CVEs — 1,651 CISA KEV, 577 EPSS-scored |
| Indicators | ~2,100 from abuse.ch, OTX, and the demo seed |
| News | 175 articles, auto-linked to actors and CVEs |
| Feeds | 18 sources, hourly |

---

## 7. What's next

**Phase 6 — Threat hunting.** Structured query builder over IOCs/actors/techniques, saved
and scheduled hunts, alerting on new matches, graph pivot view. The `HuntQuery` model
already exists and is unused.

**Phase 7 — Export and API.** STIX 2.1 / MISP / CSV / Snort export, public REST API with
the existing `ApiKey` model, scheduled reports. ATT&CK Navigator export already works
(`/api/attack/navigator`) and is a good template for the auth pattern.

**Phase 8 — Hardening.** Indicator decay (the `decayHalfLifeDays` field is set per source
but nothing applies it yet), `Indicator` partitioning if it passes ~10M rows,
backup/restore, rate limits on the public API, security review.

**Do first, before Phase 6:** move to real PostgreSQL (§4.1). Building hunting and alerting
on a database that falls over under an hourly ingest is a bad trade.

**Also outstanding:**
- Settings UI for provider API keys — the `CREDENTIAL_ENC_KEY` env var and the encrypted
  storage it implies are declared but unused; keys currently come from `.env` only.
- `/malware`, `/hunting`, `/settings`, `/audit` are still "Soon" in the sidebar.
- `recomputeIndicatorConfidence` overwrites analyst-set confidence with the max provider
  score. Correct for feed-ingested IOCs, arguably wrong for a hand-tuned one — revisit if
  it annoys you.
