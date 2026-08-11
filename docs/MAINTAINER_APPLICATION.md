# Maintainer Program Notes

This document summarizes the public maintenance posture of Pulse Intelligence for open-source
program reviews.

## Project Summary

Pulse Intelligence is an open-source, self-hosted threat intelligence platform for analysts,
junior CTI analysts, SOC teams, and students. It focuses on practical workflows: actor and
campaign tracking, IOC ingest, feed processing, enrichment, ATT&CK mapping, hunting, exports,
scheduled reports, and auditability.

## Current Maintenance Signals

- MIT license, code of conduct, contributing guide, security policy, contributors file, and
  maintainer guide are present.
- CI runs lint, typecheck, tests, audit, and build on `main` and pull requests.
- Dependabot is configured for npm and GitHub Actions.
- Public API documentation and backup/restore guidance are available under `docs/`.
- Contributor labels and starter issues are available in GitHub Issues.
- AI assistance is disclosed in `CONTRIBUTORS.md` and `MAINTAINERS.md`.

## Why Claude Helps This Project

Claude is useful for this project because CTI tooling has a wide surface area: data modeling,
feed parsing, defensive security review, documentation, API examples, and analyst-facing UI.
AI-assisted review can help catch edge cases and accelerate contributor onboarding, while the
human maintainer keeps final responsibility for security and project direction.

## Public History Note

The public Git history was cleaned before community release to remove local editor/AI tool
scaffolding and replace generic export-style commit messages with reviewable project milestones.
See `HISTORY.md` for the development timeline.
