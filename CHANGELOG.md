# Changelog

All notable changes to Pulse Intelligence will be documented here.

## Unreleased

### Added

- **Containerized deployment** — a multi-stage `Dockerfile`, `docker-entrypoint.sh`
  (auto-applies `prisma migrate deploy` on boot), and a `.dockerignore`. The
  `docker compose --profile full up -d --build` profile now runs app + worker +
  Postgres + Redis together. The image ships the full `node_modules` so
  operator scripts (`attack:sync`, `cve:catchup`, `db:seed*`, verify scripts)
  run inside the container.

### Changed

- `docker-compose.yml` worker service now runs `npm run worker` (the
  TypeScript entrypoint via `tsx`) instead of the nonexistent
  `node dist/worker.js`; app gets a `/api/health` healthcheck; the unused
  `CREDENTIAL_ENC_KEY` requirement was dropped.
- CI builds the Docker image and smoke-tests the **full compose stack** — app
  answers `/api/health`, worker reports ready — against real Postgres + Redis
  service containers.

---

## v0.2.0 - 2026-08-11

### Added

- **GreyNoise enrichment provider** — Community tier works with no API key.
  Classifies IPs as mass-scanner noise (Shodan crawlers, Censys bots) vs targeted/unknown.
  RIOT detection surfaces known-good infrastructure (Google, Cloudflare) to prevent
  false-positives. Commercial key upgrades to the full `/v2/noise/quick` endpoint.

- **Shodan enrichment provider** — InternetDB works with no API key.
  Surfaces open ports, CPEs, CVE list, hostnames, and Shodan tags for any public IP.
  Optional `SHODAN_API_KEY` upgrades to the full `/shodan/host/:ip` endpoint with
  org, ASN, country, ISP, CVSS-scored vulnerabilities, and full service banners.

- **Rich enrichment cards** on indicator detail pages — replaces the bare table with
  provider-specific views: GreyNoise classification + RIOT badge; Shodan port chips,
  CVE list with CVSS, org/ASN/geo. Generic fallback card for other providers.
  All cards show verdict badge, score, and freshness (fresh/stale relative to expiresAt).

- **Copy-defanged button** on indicator detail pages — one click copies the defanged
  value (`hxxps://evil[.]com`) to clipboard for safe pasting into tickets and email.

- **Live IOC extraction preview** on the bulk import page — extracts and previews all
  IOC types in real time as analysts type or paste, with no server round-trip.
  Two modes auto-selected by input heuristics:
  - *Line mode*: one IOC per line, comma/tab-separated values supported.
  - *Prose mode*: scans unstructured text (threat reports, emails) for embedded IOCs.
  Supported types: IPv4, IPv6, Domain, URL, SHA256, SHA1, MD5, Email, CVE, BTC address,
  Registry key, Mutex, User-agent, ASN. Color-coded type badges, expandable value table,
  dynamic submit button label showing exact count.

- **Sigma rule generator** — auto-generates ready-to-use Sigma detection rule bundles
  from actor and campaign data. Downloaded `.yml` works directly with `sigma-cli` to
  compile to Splunk SPL, Elastic EQL, Sentinel KQL, Chronicle YARA-L, and more.
  Generates network IOC rules, file hash rules, host artifact rules, and TTP-based rules
  for 9 ATT&CK techniques with false-positive filters. Download button added to actor
  and campaign detail pages.
  Endpoints: `GET /api/sigma/actor/:id`, `GET /api/sigma/campaign/:id`.

- **MITRE D3FEND countermeasures** on ATT&CK technique detail pages — maps each
  technique to the defensive techniques (Harden, Detect, Isolate, Deceive, Evict) that
  counter it. Offline mapping covers ~50 high-priority techniques from CISA top-exploited
  and Mandiant M-Trends. Links to d3fend.mitre.org for the full graph. Zero network calls.

- **360° IOC context pivot API** — `GET /api/v1/indicators/:id/context` returns
  everything the platform knows about an indicator in one authenticated call: enrichments
  (with raw provider responses), actors, campaigns, reports, and an aggregate verdict.
  Designed for SOAR playbook integration. Cache-Control: private, 60s.

### Changed

- `.env.example` updated with `GREYNOISE_API_KEY` and `SHODAN_API_KEY` documentation
  including free-tier notes and registration URLs.

---

## v0.1.0 - 2026-08-11

Initial open-source release of Pulse Intelligence.

### Added

- Threat actor, campaign, indicator, report, source, CVE, and ATT&CK tracking workflows.
- PostgreSQL/Prisma data model with analyst attribution, confidence, TLP, and audit logging.
- Session authentication, role-based access, hashed API keys, and scoped public API access.
- Indicator ingest, normalization, deduplication, whitelisting, source decay, and exports.
- Feed ingestion for CISA KEV, NVD, FIRST EPSS, abuse.ch, OTX, vendor blogs, and security news.
- Enrichment workflows for OTX, AbuseIPDB, VirusTotal, and offline stub development.
- Threat hunting query builder with templates, ATT&CK-aware fields, alerts, and match exports.
- KQL, SPL, and Lucene detection-query drafts for saved hunts.
- Scheduled Markdown reports and report generation workflow.
- Admin audit log page.
- CI, Dependabot, issue templates, pull request template, code owners, maintainer docs, roadmap,
  API docs, OpenAPI spec, backup/restore docs, and integration examples.

### Security

- Public API keys are rate limited by default.
- Baseline security headers are configured in Next.js.
- Whitelisted and expired indicators are suppressed from public API/export/hunting surfaces.
- Report bodies render as text instead of HTML.

### Notes

- This is the first public community release. Some Phase 8 hardening work remains, including
  large-table partitioning guidance and deeper deployment review.
