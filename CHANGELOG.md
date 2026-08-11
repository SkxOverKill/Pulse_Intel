# Changelog

All notable changes to Pulse Intelligence will be documented here.

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
