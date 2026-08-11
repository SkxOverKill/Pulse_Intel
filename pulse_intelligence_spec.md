# Pulse Intelligence — Threat Intelligence Platform Spec

**Status:** Phases 1–7 of 8 complete — runnable at `npm run dev` + `npm run worker`
**Created:** 2026-07-21
**Source dir:** `C:\Users\Sukesh\Downloads\Pulse Development\pulse_intelligence\`

A self-hosted Threat Intelligence Platform: threat actor / APT tracking, campaigns, IOC
management with bulk enrichment, MITRE ATT&CK mapping, automated feed ingestion, threat
hunting, and unified search. Comparable in scope to Cyble Vision or SOCRadar.

---

## 1. Locked decisions

| Decision | Choice |
|---|---|
| Stack | Next.js 16.2.x (App Router) + PostgreSQL 17 + Prisma + Redis |
| Language | TypeScript end-to-end |
| Deploy | Docker Compose, local first; VPS-portable, no serverless coupling |
| Enrichment keys | **None yet** — provider interface + stubs, real keys drop in later |
| Users | Single org, roles: `admin` / `analyst` / `readonly` |

**Why not serverless:** feed ingestion and bulk enrichment are long-running background jobs.
Serverless timeouts would force an external worker anyway. Docker Compose keeps the worker
in-process and the whole thing portable to any VPS later.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────┐
│  Next.js app (port 3000)                            │
│   ├── /app          UI (RSC + client islands)       │
│   ├── /app/api      REST API routes                 │
│   └── /lib          domain logic (shared w/ worker)  │
├─────────────────────────────────────────────────────┤
│  Worker process (same image, different entrypoint)  │
│   ├── feed ingestion    (scheduled)                 │
│   ├── enrichment queue  (rate-limited)              │
│   └── ATT&CK sync       (weekly)                    │
├──────────────┬──────────────────────────────────────┤
│ PostgreSQL 17│ Redis 7 (BullMQ queues + resp cache) │
└──────────────┴──────────────────────────────────────┘
```

Four containers: `app`, `worker`, `postgres`, `redis`. The worker shares `/lib` with the app —
domain logic is written once and imported by both. No separate backend repo.

---

## 3. Data model

STIX-informed but relational and pragmatic — not a literal STIX store. Prisma schema.

### Core entities

**`ThreatActor`** — the centerpiece for APT tracking.
`id`, `name`, `aliases[]` (APT29 / Cozy Bear / Midnight Blizzard / NOBELIUM — cross-vendor
naming is the hard part), `description`, `country`, `motivation` (espionage | financial |
hacktivism | destruction), `sophistication`, `firstSeen`, `lastSeen`, `active`,
`attackGroupId` (links to ATT&CK G-number), `confidence`, `tlp`.

**`Campaign`** — `id`, `name`, `actorId?`, `description`, `startDate`, `endDate?`,
`targetSectors[]`, `targetCountries[]`, `status`.

**`Indicator`** (IOC) — `id`, `type` (ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 |
email | cve | btc-address | registry-key | mutex), `value`, `normalizedValue` (defanged and
lowercased for dedup), `firstSeen`, `lastSeen`, `confidence` (0-100), `severity`, `tlp`,
`tags[]`, `sourceId`, `expiresAt?`, `whitelisted`.
→ **Unique index on `(type, normalizedValue)`.** Dedup at ingest is non-negotiable; feeds
overlap heavily and without this the table becomes garbage within a week.

**`Enrichment`** — one row per (indicator, provider) lookup.
`indicatorId`, `provider`, `rawResponse` (jsonb), `verdict`, `score`, `fetchedAt`,
`expiresAt`. Cached, never re-fetched while fresh. This table is what keeps you inside the
free-tier quotas.

**`Malware`** / **`Tool`** — name, aliases, family, type, `attackId` (S-number).

**`Technique`** — ATT&CK. `attackId` (T1566.001), `name`, `tactic`, `domain`
(enterprise|mobile|ics), `description`, `platforms[]`, `dataSources[]`, `detection`,
`isSubtechnique`, `parentId`, `deprecated`, `attackVersion`.

**`Report`** — analyst-authored or ingested intel reports. `title`, `body` (markdown),
`published`, `authorId`, `tlp`, `confidence`, `sourceUrl`.

**`Source`** — a feed or manual origin. `name`, `type` (rss|taxii|misp|csv|json|manual),
`url`, `enabled`, `schedule` (cron), `lastRunAt`, `lastStatus`, `defaultTlp`,
`defaultConfidence`, `parserConfig` (jsonb).

**`NewsItem`** — current threat news. `title`, `summary`, `url`, `publishedAt`, `sourceId`,
`tags[]`, `relevanceScore`, `linkedActorIds[]`, `linkedCveIds[]`.

**`Vulnerability`** — `cveId`, `description`, `cvssV3`, `cvssV4`, `epssScore`,
`knownExploited` (CISA KEV flag), `published`, `vendorRefs[]`.

**`HuntQuery`** — saved threat hunts. `name`, `description`, `query` (structured JSON),
`schedule?`, `lastRunAt`, `notifyOnHit`.

**`User`**, **`Session`**, **`AuditLog`**, **`ApiKey`**.

### Relations (join tables, all many-to-many)

`ActorTechnique`, `ActorMalware`, `ActorTool`, `ActorIndicator`, `CampaignActor`,
`CampaignTechnique`, `CampaignIndicator`, `ReportActor`, `ReportIndicator`,
`ReportTechnique`, `ActorTargetSector`.

Every join row carries `confidence` and `addedBy` — attribution is opinion, not fact, and the
UI must show who claimed what. This is the difference between a real TIP and a database
with a nice frontend.

### Postgres specifics

- `pg_trgm` extension → fuzzy search on actor names and aliases.
- `tsvector` generated columns + GIN indexes on `Report.body`, `NewsItem.summary`,
  `ThreatActor.description` → full-text search.
- `jsonb` + GIN on `Enrichment.rawResponse` → query raw provider data without reshaping it.
- Partition `Indicator` by `firstSeen` month if it passes ~10M rows (defer; note it in code).

---

## 4. Modules

### 4.1 Threat Actor / APT tracking
Actor profile page: overview, aliases with source attribution, timeline of campaigns,
ATT&CK technique heatmap (their TTPs highlighted on the matrix), associated malware/tools,
targeted sectors and countries (map), linked IOCs, linked reports, change history.
Actor comparison view — diff two actors' technique sets side by side.

### 4.2 Campaigns
Timeline visualization, actor attribution with confidence, victimology, IOC set, technique
set, linked reporting. Campaign → actor promotion workflow (unattributed clusters get names).

### 4.3 IOC management
- Bulk paste / CSV / STIX upload → parse, defang-normalize, dedup, tag, enrich.
- Automatic type detection from value shape.
- Whitelist system (RFC1918, CDN ranges, Alexa/Tranco top domains) — prevents the classic
  TIP failure of blocking `8.8.8.8` because a feed listed it.
- Confidence decay: IOCs age out. Configurable half-life per source and per type.
  (An IP is stale in 30 days; a SHA256 is good forever.)
- Bulk export: CSV, STIX 2.1, MISP JSON, Snort/Suricata rules, firewall block lists.

### 4.4 Enrichment (the rate-limit problem)
**This is the hardest engineering constraint in the project.**

| Provider | Free tier | Implication |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | ~20 IOCs enriched per 5 min. A 10k paste = 20 days. |
| AbuseIPDB | 1,000 checks/day | Better, and has a real bulk endpoint. |
| OTX | Generous / effectively unlimited | Primary source; use it first. |

Design consequences, all mandatory:
1. **Provider interface** — `EnrichmentProvider { name, supports(type), lookup(ioc), parseVerdict() }`.
   Every provider behind it. Ships with `StubProvider` returning deterministic fake data
   derived from a hash of the IOC value, so the whole pipeline is buildable and testable
   with zero API keys.
2. **Token-bucket rate limiter in Redis**, per provider, configured from a declarative
   quota config. Not `setTimeout` — it must survive worker restarts and be correct across
   concurrent workers.
3. **Cache-first**: never call a provider if a non-expired `Enrichment` row exists. TTL per
   provider (VT 7d, AbuseIPDB 1d).
4. **Queue with priority** (BullMQ): analyst-triggered lookups jump ahead of bulk feed
   enrichment. A human waiting beats a background job.
5. **Honest UI**: bulk job shows queued / in-progress / done / quota-blocked counts and an
   ETA computed from remaining quota. Never pretend a 10k job will finish today.
6. **Graceful degradation**: quota exhausted → job pauses and resumes at quota reset, does
   not fail.

Providers to implement: VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, URLScan, GreyNoise,
Have I Been Pwned. All stubbed initially; keys added via Settings UI (encrypted at rest).

### 4.5 MITRE ATT&CK
Sync **ATT&CK v19.1** (current as of May 2026) from the `mitre-attack/attack-stix-data`
STIX 2.1 collection bundles. Weekly job; version-pinned with manual upgrade approval so a
MITRE release never silently reshapes your mappings.

Features: full navigable matrix (enterprise/mobile/ICS), technique detail pages, coverage
heatmap (which techniques your IOCs and actors touch), ATT&CK Navigator layer export (JSON),
gap analysis vs. tracked actors, technique → detection guidance.

### 4.6 Feed ingestion
Pluggable parsers: RSS/Atom, TAXII 2.1, MISP, CSV (column-mapped), JSON (JSONPath-mapped),
plain-text IOC lists.

Pipeline: `fetch → parse → normalize → dedup → whitelist-filter → confidence-score → persist → queue-enrich`.

Ships with free sources preconfigured: CISA KEV, CISA advisories, abuse.ch (URLhaus,
ThreatFox, Feodo, MalwareBazaar), OTX pulses, Tor exit nodes, NVD CVE feed, EPSS scores,
plus vendor blogs for news (Mandiant, CrowdStrike, Talos, Unit42, Recorded Future, The DFIR
Report, BleepingComputer, The Record).

Per-source health dashboard: last run, items ingested, error rate, dedup ratio. A silently
dead feed is worse than no feed.

### 4.7 Threat hunting
Structured query builder over IOCs, actors, techniques, and reports. Saved hunts. Scheduled
hunts that alert on new matches. Pivot navigation — click any entity, see everything related,
with relation confidence shown. Optional graph view (actor ↔ campaign ↔ IOC ↔ technique).

### 4.8 News & dashboard
Aggregated threat news, auto-tagged and auto-linked to tracked actors/CVEs by keyword and
alias matching. Home dashboard: new IOCs (24h), active campaigns, KEV additions, feed
health, enrichment quota status, recent high-severity items, actor activity.

### 4.9 Search
Unified search across all entity types. Postgres FTS + `pg_trgm` fuzzy matching.
Type-ahead, filters (type / TLP / confidence / date / source / tag), saved searches.
Deliberately **not** Elasticsearch — Postgres FTS is sufficient at this scale and one less
container to run. Revisit only if search latency becomes a real complaint.

### 4.10 Platform
Auth (email + password, Argon2id, session cookies), RBAC middleware, audit log on every
mutation, API keys for programmatic access, rate-limited public REST API, TLP handling
enforced at the query layer, encrypted secret storage for provider keys.

---

## 5. Build order

Each phase ends in a working, runnable state. No phase depends on API keys.

**Phase 1 — Foundation** ✅ *done 2026-07-21*
Next.js 16.2 + Prisma 7 + Postgres. Full core schema, initial migration, seed. Argon2id
auth, DB-backed sessions, RBAC, audit log. App shell: sidebar, top bar, Pulse dark-navy
theme. → *Runnable, loginable, empty.*

Deviations from the original plan, all forced by the machine and both reversible:
- **Docker deferred.** `hypervisorlaunchtype` is `Off`, so WSL2 and Docker Desktop both
  fail. `npx prisma dev` provides a real local Postgres (pg_trgm + btree_gin confirmed
  working), which covers Phases 1–3. `docker-compose.yml` is written and ready for the VPS.
  Redis — and therefore the reboot — isn't needed until Phase 4.
- **`prisma migrate dev` is unusable** against that dev server (P1017). Replaced with
  `scripts/migrate-offline.ts`, which produces identical migration files and history.
  Delete it once on real Postgres.
- **Search indexes deferred to Phase 2.** Extensions are created in the init migration, but
  trigram/FTS indexes ship with the search implementation rather than creating Prisma schema
  drift a phase early.

**Phase 2 — Core entities** ✅ *done 2026-07-21*
CRUD + list/detail UI for Actors, Campaigns, Indicators, Reports, Sources. Relations and
the pivot UI. Search (FTS + trigram). → *A usable manual TIP.*

Built: 23 routes. Actor profiles with attributed aliases; campaign attribution carrying
confidence + provenance; IOC bulk import with refang, auto type detection, dedup and
whitelisting; reports with one-click IOC extraction; feed/source config; global search that
redirects straight to an indicator when the query *is* one.

Notable decisions:
- **IOC parsing and whitelisting are unit-tested** (52 tests). The parser had two real bugs
  the tests caught — a refang regex emitting `httpp://`, and `detectType` rejecting the
  trailing root dot that `normalize` was written to strip. Both are the kind of defect that
  would silently split one indicator into several rows.
- **`src/lib/ioc/*` is deliberately not `server-only`.** The Phase 4/5 worker is a plain
  Node process sharing `src/lib`, and `server-only` throws on import outside a bundler —
  marking shared domain logic with it would break the worker.
- **Report bodies render as preformatted text, not HTML.** Reports routinely contain live
  malicious URLs and attacker-controlled strings; a markdown-to-HTML renderer would be an
  XSS sink. A sanitising renderer can come later if it earns its keep.
- **Search indexes are expression indexes, not generated `tsvector` columns**, so Prisma
  stays the single source of truth for columns and never tries to drop them.

Known issue, unresolved: intermittent `P1017 / ConnectionClosed` in the dev server log when
a build or seed script runs against the local dev Postgres at the same time as `next dev`.
Not reproducible from an idle connection alone (tested to 60s, with and without idle
expiry), so it is believed to be connection pressure on the small dev server rather than a
pooling bug. Not observed against a normal Postgres. See the comment in `src/lib/db.ts`.

**Phase 3 — ATT&CK** ✅ *done 2026-07-21*
STIX bundle sync, technique tables, matrix UI, actor/campaign technique mapping, heatmap,
Navigator export. → *ATT&CK-mapped intel.*

Ingested v19.1: **943 techniques, 41 tactics** across enterprise/mobile/ICS, plus 634 of
MITRE's own group→technique mappings applied to the 8 tracked actors. Matrix shows 43%
coverage of enterprise techniques.

Three things the real data forced, none of which were guessable from the v18-era docs:
- **Detection moved off the technique object.** Zero of 858 enterprise attack-patterns
  carry `x_mitre_detection` or `x_mitre_data_sources` in v19. Both now live behind
  `x-mitre-detection-strategy` → `x-mitre-analytic` objects reached via `detects`
  relationships. Following that chain recovered detection prose for 697 techniques and data
  sources for 652, instead of shipping two permanently empty fields.
- **`Technique.tactic` had to become `tactics String[]`.** 21% of techniques belong to more
  than one tactic; a scalar column silently drops them from every matrix column but one.
- **A domain can ship multiple matrices.** Mobile has the legacy "Network-Based Effects"
  (2 tactics) listed *before* the real "Mobile ATT&CK" (12). Reading only the first matrix
  yielded 2 tactics instead of 14 and orphaned every technique in the other 12.

Coverage counts are distinct actors, not summed mappings — an early version reported
"15 actors" on a technique when only 8 actors existed, because parent techniques summed
their sub-technique counts.

**Migration drift is now enforced, not just documented.** `prisma migrate diff` emits
`DROP INDEX` for all 13 raw-SQL search indexes on every run, because they do not appear in
schema.prisma. `scripts/migrate-offline.ts` refuses to apply any migration that drops one
and prints the SQL for hand-editing instead.

**Phase 4 — Enrichment engine** ✅ *done 2026-07-21*
Provider interface, Redis token-bucket limiter, BullMQ queue, cache layer, stub provider,
bulk enrichment UI with honest progress. VT + AbuseIPDB + OTX behind the interface, all
three keys live and verified. → *Bulk enrichment works.*

Redis was available all along — **Memurai 7.2.5** was already listening on :6379, so the
hypervisor change was never needed.

The limiter's atomicity is proven, not assumed: `npm run verify:enrichment` fires 20
concurrent requests at a 4/min quota and asserts exactly 4 are allowed. A read-then-write
in JS leaks tokens under that load; the single Lua script does not.

**Phase 5 — Feed ingestion** ✅ *done 2026-07-21*
Parser framework, scheduler, dedup + whitelist + confidence pipeline, preconfigured free
sources, feed health dashboard. → *Platform fills itself.*

18 sources on hourly schedules. Verified live: **1,651 KEV CVEs, ~2,100 indicators, 175
news articles**, with news auto-linked to actors (by name *and* alias) and CVEs.

Bugs the live run exposed:
- **EPSS/CVSS ordering needed `nulls: "last"`.** Postgres defaults to NULLS FIRST on DESC,
  so 1,571 unscored CVEs sorted above the 577 scored ones — the dashboard was claiming an
  "EPSS ranking" while showing unranked rows.
- **BullMQ rejects `:`** in both queue names and custom job ids.
- **Dynamically-shaped `upsert` broke the dev Postgres** (`08P01`). Replaced with a
  fixed-shape read-then-merge, which also states the "don't clobber another feed's fields"
  intent explicitly.
- **vitest could not resolve `@/`** until a test touched a runtime (non-type) import.

**Blocking issue for real use:** the `prisma dev` Postgres wedged under a full feed ingest
and needed a process kill plus stale-lock cleanup. It also cannot do `migrate dev`,
introspection, or dynamically-shaped upserts. Install real PostgreSQL
(`winget install PostgreSQL.PostgreSQL.17` — no virtualization required) before relying on
hourly automation.

**Phase 6 — Hunting & news**
Query builder, saved/scheduled hunts, alerting, news aggregation + auto-linking, main
dashboard. → *Proactive, not just a catalog.*

**Phase 7 — Export & API**
STIX/MISP/CSV/Snort export, public REST API + keys + docs, ATT&CK Navigator layers,
scheduled reports. → *Integrates with other tools.*

**Phase 8 — Hardening**
Perf indexes, IOC partitioning if needed, backup/restore, rate limits, security review,
deployment docs.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| **VT free tier makes "bulk" nearly useless** | Cache-first, dedup, OTX-first ordering, honest ETAs, priority queue. Accept and surface the limit rather than hiding it. |
| Actor alias chaos across vendors | Alias table with per-source attribution; never collapse aliases silently. |
| Feed noise poisoning the IOC set | Whitelists, per-source confidence, decay, dedup ratio monitoring. |
| ATT&CK version drift breaking mappings | Version-pinned sync, manual upgrade approval, mappings keyed by stable ATT&CK ID. |
| Scope sprawl (this spec is large) | Phase gates. Each phase must run before the next starts. |
| IOC table growth | Unique index + dedup from day one; partition later if warranted. |

---

## 7. Open items (decide when reached)

- Graph visualization library for the pivot view (Phase 6) — Cytoscape vs. D3 vs. skip.
- Whether to add a MISP sync connector (Phase 7) — depends on whether you run MISP.
- Alerting transport: email vs. webhook vs. both (Phase 6).
- Public API auth model detail: bearer keys vs. HMAC signing (Phase 7).
