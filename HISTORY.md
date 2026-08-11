# Project History

Pulse Intelligence started as a self-hosted threat intelligence platform prototype and is now being
prepared as an open-source community project for analysts, junior CTI analysts, SOC teams, and
students.

## Timeline

### 2026-07-21

- Built the initial platform foundation: Next.js app shell, PostgreSQL/Prisma data model, session
  auth, RBAC, audit logging, actor/campaign/indicator/report/feed workflows, and search indexes.
- Added MITRE ATT&CK import support and matrix views.
- Added enrichment, feed ingestion, Redis queues, and the first automated feed catalogue.

### 2026-07-22 to 2026-07-23

- Expanded the project into threat hunting, public exports, scoped API keys, scheduled reports,
  CVE catch-up/pruning, news linking, dashboard charts, and operational handover notes.
- Moved the deployment target from a fragile local dev database setup toward real PostgreSQL and
  Redis-compatible services.

### 2026-08-11

- Prepared the project for a public open-source release.
- Reworked public documentation, contribution guidance, security reporting, CI, Dependabot, health
  checks, and repository metadata.
- Cleaned local AI/editor workspace files out of the public repository while keeping AI assistance
  credited in `CONTRIBUTORS.md`.
- Rebuilt public Git history into clear, reviewable commits so the repository reads like a maintained
  open-source project rather than an exported working folder.

## AI Assistance

Claude and Codex have been used as development assistants for implementation support, review, and
documentation. Project direction, maintenance decisions, public release decisions, and security
decisions remain human-owned.

## Notes For Reviewers

The public Git history was cleaned before community release to remove local tool scaffolding and
replace generic export-style commit messages with meaningful project milestones. The project itself
was already being developed before the public release cleanup.
