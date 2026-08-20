# Pulse Intelligence — Handover

Last updated: **2026-08-20**
Status: **Phases 1–8 hardening in progress.** 232 tests, clean build. Running on a
Prisma-managed PostgreSQL dev server (§4.1 resolved). Provider-role migration notes superseded
by the `ProviderCredential` table; see the confidence-lock and backup-smoke notes in
"Also outstanding" below.

A self-hosted Threat Intelligence Platform — APT tracking, campaigns, IOC management with
bulk enrichment, MITRE ATT&CK, automated feed ingestion, search, and threat hunting.

- **Plan and rationale:** [`../pulse_intelligence_spec.md`](../pulse_intelligence_spec.md)
- **Setup and day-to-day commands:** [`README.md`](README.md)
- **This file:** how to pick the project up on another machine, and what not to break.

---

## 1. Moving to the RDP box — read this first

Two things will bite you, in this order.

### 1.1 The repo has no remote

`git remote -v` is empty. The code exists only in this folder until a GitHub remote is added.

For the open-source community release, create or choose the public GitHub repository, then:

```bash
cd "C:\Users\Sukesh\Downloads\Pulse Development\pulse_intelligence"
git remote add origin https://github.com/<you>/pulse-intelligence.git
git push -u origin main
```

Then on any new machine: `git clone https://github.com/<you>/pulse-intelligence.git`

Do not commit `.env`, real provider keys, database dumps, or private investigation data. The
application source is safe to publish; deployment state is not.

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

### 2.4 Sharing a public link (temporary — set up 2026-07-23)

For letting people outside this machine reach it: run **production**, not dev
(`npm run build && npm run start` — dev mode is fine for local iteration, not for anyone else's
traffic), then a Cloudflare quick tunnel: `cloudflared.exe tunnel --url http://localhost:3000`
(binary downloaded to `%TEMP%/installers` this session; grab a fresh copy from
https://github.com/cloudflare/cloudflared/releases/latest if it's gone). No account, no config,
no firewall/router changes — it's an outbound-only connection to Cloudflare's edge.

**The URL is ephemeral.** It's tied to the `cloudflared` process; killing it (or a machine
restart) kills the URL, and a new run gets a new random one — there's no way to keep the same
link across restarts without a Cloudflare account and a named tunnel. Treat any link handed out
this way as short-lived.

**Known risk, accepted, not fixed:** the seed admin/analyst/viewer passwords are still the
defaults printed in this file (§ below) and this repo's own commit history/chat — anyone who
has seen them can log in as ADMIN through the public link. Rotate them at **Settings → the
key icon in the topbar → Change password** (self-service, any signed-in user, no admin
needed). If this stops being "show a few friends" and becomes anything longer-lived,
also rotate `SEED_PASSWORD` and manually update the three `User.passwordHash` rows
(re-running `db:seed` won't touch an existing user's password — see the comment in
`prisma/seed.ts`).

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
scripts/                       CLI: attack-sync, install-feeds, migrate-offline, cve-catchup,
                                verify-enrichment/hunting/api/reports
```

---

## 4. Known issues and traps

### 4.1 RESOLVED — now on real PostgreSQL 17

As of 2026-07-22 this runs against a native PostgreSQL 17 service on the RDP box
(`postgresql-x64-17`, port 5432), not the old `prisma dev` toy. Databases `pulse` and
`pulse_shadow` exist; `.env` points at them. The old wedging / `P1017` / dynamic-upsert
problems are gone.

Two things still bite, both worked around:

- **`prisma migrate dev` hangs in a non-interactive shell.** It waits on a prompt that
  can't render, and leaves a `node` process holding a Postgres advisory lock, so the next
  migrate fails `P1002`. Apply existing migrations with **`npx prisma migrate deploy`**
  instead. If a lock sticks, kill stray `node` processes and retry.
- **The §4.2 DROP-INDEX drift is still real.** `scripts/migrate-offline.ts` is kept (not
  deleted) precisely because it guards it — when I added the `HuntAlert` model, the diff
  again wanted to drop all 13 search indexes. The migration
  `20260721… _add_hunt_alerts` was hand-authored to keep only the `CREATE TABLE`. Read
  §4.2 before generating any migration.

Still open (low priority): the sequential-query comments in `src/app/(app)/page.tsx` and
`enrichment/page.tsx` were written for the toy DB's concurrency limits and can go back to
`Promise.all` on real Postgres.

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

### 4.5 NVD needs an API key or CVE data quietly goes stale

The hourly "NVD Recent CVEs" feed (`src/lib/feeds/run.ts`, `nvd-recent` handler) only queries
a rolling **24h `lastModStartDate` window** — correct for staying current, useless for
catching up. Without `NVD_API_KEY` set, NVD caps requests at 5/rolling-30s and intermittently
403s keyless traffic; the feed can report `lastStatus: ok` while genuinely making no progress,
which is how the CVE table drifted to being ~7 weeks stale before anyone noticed.

Fixed 2026-07-23: `NVD_API_KEY` is now in `.env` (get one free, instantly, at
https://nvd.nist.gov/developers/request-an-api-key), sent via the `apiKey` header
(`nvdHeaders()` in `run.ts`). **`npm run cve:catchup [-- --days N]`** is a one-time backfill —
unlike the hourly job, it pages through everything NVD *published* in the last N days (default
30), so a stale DB catches up in one run instead of trickling in 24 hours at a time. Ran once
already: pulled 9,697 CVEs from the last 30 days. Re-run it (with a larger `--days`) any time
the data looks stale again; the hourly job alone is only good at staying current once it *is*
current.

### 4.6 Vulnerability retention — strict 90-day window, including KEV

The NVD feed pulls in the full public CVE stream, which grows unbounded with nothing to prune
it. `pruneOldVulnerabilities()` (`src/lib/feeds/run.ts`) now runs automatically as part of every
hourly `nvd-recent` job: deletes every vulnerability whose `publishedAt` is older than
`VULN_RETENTION_DAYS` (90 — "last 2-3 months," a product decision, not a technical constraint) —
**including CISA KEV entries**, and including rows with no `publishedAt` at all (treated as
unknown-age, pruned rather than kept forever).

This was **not** the first cut. The first version exempted KEV rows on the reasoning that
"actively exploited" stays relevant regardless of age (Log4Shell is still on CISA's list).
That's true, but the product call landed the other way — a self-hosted single-tenant instance
would rather see a short, current list than carry `CVE-2021-44228` forever, and the default
EPSS-first sort meant KEV rows dominated page 1 regardless of the retention window, which read
as "still showing 2021-2024 data" even after pruning. A second attempt fell back to
`kevDateAdded` for undated KEV rows (when CISA flagged it, not when NVD published it) — that
let `CVE-2008-4250` stay on a "last 3 months" list because it was *re-flagged* recently, which
is exactly the stale-looking noise this was supposed to remove. Landed on: judge age by
`publishedAt` only, no exemptions, no fallback. If a KEV exemption is wanted back, gate the
`deleteMany` on `knownExploited: false` — but expect the "page 1 still looks old" complaint to
return with it, because the EPSS-first sort will keep surfacing whatever KEV rows survive.

Manual/immediate cleanup: `npm run vuln:prune [-- --days N]`. As of 2026-07-23: 10,608 CVEs
(down from a peak of 12,345), oldest `publishedAt` in the table is ~90 days out, 15 CISA KEV
entries remain (all recently published, not just recently flagged).

### 4.7 `<body>` needs `suppressHydrationWarning`

Browser extensions (Grammarly, password managers) inject `data-*` attributes onto `<body>`
before React hydrates, which React reports as a hydration mismatch — a false positive; the
extension modified the DOM, the app didn't do anything wrong. `suppressHydrationWarning` on the
root layout's `<body>` (`src/app/layout.tsx`) is the standard, documented fix. Don't add it
anywhere deeper in the tree — it silences real mismatches too, and `<body>` is the only element
extensions commonly touch.

### 4.8 Vulnerabilities page sorts newest-first; campaigns auto-link to news like actors do

`/vulnerabilities` now orders by `publishedAt desc` first, EPSS/CVSS as the tiebreaker (was the
reverse — see §4.6 for why that read as stale). The dashboard's separate "Highest-risk exploited
CVEs" widget is untouched; it's deliberately EPSS-first and correctly labeled as such.

`NewsItem.linkedCampaignIds` (new field, mirrors `linkedActorIds`/`linkedCveIds`) is populated by
`linkNewsItem()` in `src/lib/feeds/run.ts`, now exported so `scripts/relink-news.ts` can also
call it — that script re-scans **every** existing news item against the current actor/campaign
roster, because a campaign added today never retroactively links to an article ingested
yesterday otherwise (`ingestNews` only links at ingest time). Run `npm run news:relink` after
adding campaigns or actors to the seed.

**Matching is exact-name, word-boundary — same mechanism as actor linking, same limitation.**
"Scattered Spider" appears verbatim in real articles and matches fine; a constructed title like
"MGM Resorts & Caesars Entertainment Ransomware Attacks" almost never will, because no journalist
types the analyst-style campaign name verbatim. Actor linking works well in practice for this
reason; campaign linking will mostly stay empty until real coverage happens to phrase it that
way. This was a known, accepted tradeoff, not a bug — a fuzzy/keyword matcher would need a
`campaignAliases`-style field (mirroring `ActorAlias`) to do meaningfully better, which wasn't
built. If this starts to matter, that's the extension point.

`prisma/seed-demo.ts` grew from 4 to 15 campaigns — real, publicly-documented incidents
(3CX, JumpCloud, MGM/Caesars, Snowflake, UK retail DragonForce attacks, WinRAR CVE-2023-38831,
Industroyer2, KV Botnet, Black Basta, US state government zero-days, Teams device-code phishing),
each attributed to one of the existing 8 actors. `npm run db:seed:demo` is idempotent
(`upsert` on name) — safe to re-run after adding more.

### 4.9 SOC dashboard — real charts, hand-rolled SVG, no chart library

The `/` dashboard (`src/app/(app)/page.tsx`) grew from stat tiles + two lists into a proper
SOC-style overview: two 30-day trend lines (new indicators/day, new CVEs published/day —
computed directly from `Indicator.createdAt` / `Vulnerability.publishedAt`, **no separate
snapshot table**, so history exists from day one instead of only after a new table starts
accumulating rows) plus four distribution bar charts (indicator severity, indicator types,
vulnerability CVSS band, ATT&CK tactic coverage — the last one reuses `getMatrix()` from
`src/lib/attack/matrix.ts` rather than a new query).

- **`src/components/ui/charts.tsx`** (`HorizontalBarChart`) is deliberately **not** `"use
  client"` — it has no interactivity, so it stays server-rendered, which is the only reason
  the dashboard can pass it a plain `formatValue` function prop from a Server Component.
- **`src/components/ui/trend-area.tsx`** (`TrendArea`) *is* `"use client"` (hover state,
  `useId` for the gradient). It used to live in the same file as the bar chart — that broke
  production with "Functions cannot be passed directly to Client Components," because once a
  file is `"use client"`, every component it exports becomes one, and passing a function prop
  from the server page to *any* of them fails serialization, not just the one that needs it.
  If you add a third chart type, decide up front whether it needs client interactivity and
  put it in the right file — don't default to bolting it onto whichever file is closest.
- **Categorical palette** (`--color-chart-1..6` in `globals.css`) is not eyeballed — run
  through the project's dataviz skill validator against this app's actual dark surface
  (`#0d1626`), not the skill's generic default surface. Severity/CVSS-band bars reuse the
  existing `--color-sev-*` tokens instead of the categorical palette — a status color must
  never be reassigned as "series 4" (dataviz skill's rule, and it'd also be confusing: a
  categorical bar happening to render sev-critical red for something that isn't critical).
- Every dashboard query runs through one `Promise.all` — the old sequential-query pattern
  (see §4.1) was for the fragile `prisma dev` toy DB; on real Postgres, ~14 concurrent queries
  is fine and the page would otherwise be visibly slower for no reason.
- **Not built:** the graph pivot view (actor ↔ campaign ↔ IOC ↔ technique) the spec mentions
  as optional. Scoped out of this pass to keep it shippable in one sitting; still open if
  wanted later — see spec §7's undecided Cytoscape/D3/skip choice.

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
| Campaigns | 15 real, publicly-documented campaigns (2017-2025), attributed to the 8 actors |
| ATT&CK | 943 techniques, 41 tactics (v19.1), 634 MITRE group mappings |
| Vulnerabilities | 10,608 CVEs — strict 90-day retention, no exemptions (§4.6), 15 CISA KEV, newest-first |
| Indicators | ~2,000 from abuse.ch, OTX, and the demo seed |
| News | 194 articles, auto-linked to actors, CVEs, and campaigns (exact-name match) |
| Feeds | 18 sources, hourly |

---

## 7. What's next

**Phase 6 — Threat hunting.** ✅ *done 2026-07-22.* Structured query builder over the
indicator set (`/hunting`), saved + scheduled hunts, and alerting on new matches.

- **Engine** is `src/lib/hunting/`: `schema.ts` (field catalogue + AST validation, kept
  dependency-free so the client builder can import it), `compile.ts` (AST → Prisma
  `where`), `run.ts` (preview + the scheduled runner). 20 unit tests in `query.test.ts`.
- **Whitelisted indicators are never matched** — the compiler forces `whitelisted: false`
  regardless of the query, and `whitelisted` is deliberately not a huntable field (design
  rule 3). A test and `npm run verify:hunting` both assert this.
- **"New match" alerting** compares against `lastRunAt` and only fires on indicators
  created since — a scheduled hunt must not re-alert on the same rows every hour. New
  `HuntAlert` model records each hit; the worker has a `pulse-hunts` queue + per-hunt cron
  scheduler mirroring feeds.
- **`npm run verify:hunting`** exercises the whole path against the real DB (compile →
  count → run → alert → no-re-alert) and cleans up after itself.
- Deliberately skipped for now: the graph pivot view (spec §4.7 calls it optional; §7
  leaves the library choice open). Pivot navigation already exists via entity detail pages.

**Phase 7 — Export and API.** ✅ *done 2026-07-22.*

- ✅ **IOC export done.** `src/lib/export/formats.ts` — CSV, STIX 2.1 bundle, MISP event
  JSON, Snort/Suricata rules. Pure/testable (15 tests in `formats.test.ts`). Served by
  `src/app/(app)/indicators/export/route.ts`, driven by the Export menu on `/indicators`;
  the download carries the current q/type/severity filters. **Whitelisted indicators are
  never exported** — the route forces `whitelisted: false` and there is no param to ask for
  them (design rule 3). Every export writes an `EXPORT` audit row.
  - STIX ids are deterministic (hash of type+normalizedValue) so re-exporting is idempotent.
    Types with no clean STIX observable (CVE, USER_AGENT, BTC_ADDRESS) are omitted from the
    bundle, not faked. Snort only emits rules for network observables and lists the rest in
    a trailing comment.
- ✅ **Public REST API done.** `src/lib/auth/apikey.ts` (generate/hash a key — same
  hash-only-storage pattern as session tokens) + `src/lib/api/auth.ts`
  (`requireApiKey(request, scope?)`, the per-route gate — `proxy.ts` deliberately excludes
  `/api`, so every route authenticates itself, same as `/api/attack/navigator` already did).
  Endpoints: `GET /api/v1/indicators` (+`/:id`, +`?format=csv|stix|misp|snort` reusing the
  export formatters) and `GET /api/v1/actors` (+`/:id`, techniques/malware/tools each with
  their own confidence — rule 1 again). Key management UI at `/settings` (ADMIN-only,
  raw key shown exactly once at creation, never stored). `npm run verify:api` exercises
  auth failure modes, scope enforcement, and — the one that matters — confirms a
  whitelisted indicator 404s on the public API exactly like a nonexistent one, in both
  list totals and the detail route.
- ✅ **Scheduled reports done.** `src/lib/reports/generate.ts` builds a markdown summary
  of everything that changed in a window (new indicators by severity, new actors/campaigns,
  CISA KEV additions, hunt alerts, feed health) — same signals as the dashboard, scoped to a
  date range instead of "right now". `src/lib/reports/run.ts` files it as a normal `Report`
  row with **no `authorId`**, which is how the UI tells a generated report from an
  analyst-authored one without a fake "system" user account. New `ScheduledReport` model +
  `pulse-reports` queue + worker cron scheduler, mirroring hunts exactly. UI at
  `/reports/scheduled` (linked from the Reports page header). `npm run verify:reports`
  checks the generator's counts against the real DB and that back-to-back runs don't
  slug-collide or duplicate.

**Phase 7 is complete.**

**Phase 8 — Hardening.** Indicator decay (shipped: `decayHalfLifeDays` is set per
source, ingest sets `expiresAt` via `src/lib/ioc/decay.ts`, re-seen indicators slide
their expiry, `activeIndicatorWhere` filters exports/API/pages). Backup/restore shipped:
`db:backup`/`db:restore` (see `docs/BACKUP_RESTORE.md`) plus a round-trip smoke test
(`npm run db:verify-backup`, run in CI against the compose stack). Rate limits on the
public API shipped (per-API-key, Redis fixed-window in `src/lib/api/rate-limit.ts`).
Remaining:
`Indicator` partitioning if it passes ~10M rows, security review.

**Also outstanding:**
- Backup/restore round-trip smoke test shipped (Phase 8.6b): `npm run
  db:verify-backup` (`scripts/verify-backup-restore.ts`) dumps `DATABASE_URL`,
  restores into a scratch DB, and diffs schema-only + data-only pg_dumps of
  source vs restored. Needs pg_dump/pg_restore/psql on PATH and CREATEDB for
  the DATABASE_URL role. CI `docker` job seeds demo data then runs it in the
  app container (`docker compose exec -T app npm run db:verify-backup`); the
  runtime image now ships `postgresql-client`. Pure URL helpers in
  `src/lib/backup/urls.ts` (+4 tests).
- Indicator confidence locking shipped (Phase 8.6): an analyst can pin an
  indicator's confidence from the detail page. A pinned value
  (`confidenceLocked`) is never overwritten by `recomputeIndicatorConfidence`;
  unlock to hand control back to the provider-max reconciliation. Decision
  logic is the pure `pickIndicatorConfidence` in
  `src/lib/enrichment/confidence.ts`; the server action is
  `updateIndicatorConfidence` in `src/app/(app)/indicators/actions.ts` (audited);
  `Indicator.confidenceLocked` column added by migration
  `20260819000000_add_indicator_confidence_lock`.
- Settings for provider API keys shipped (Phase 8.5): keys are stored encrypted
  in a `ProviderCredential` table (AES-256-GCM under `CREDENTIAL_ENC_KEY`) and
  served through the sync cache in `src/lib/enrichment/secrets.ts`. A DB-set
  key wins over the same key in `.env`; the worker re-hydrates the cache on its
  5-minute schedule sync. `nvd` keys for the CVE/KEV feeds go through the same
  resolver. If `CREDENTIAL_ENC_KEY` is rotated, previously stored keys stop
  decrypting — clear and re-enter them from Settings.
- The RDP box has no `winget` (Win10 LTSC). Node 24 / PostgreSQL 17 / Memurai were
  installed from direct MSI/EXE downloads. `node`/`npm`/`psql` are not on the bash PATH by
  default — prepend `/c/Program Files/nodejs` and `/c/Program Files/PostgreSQL/17/bin`.
