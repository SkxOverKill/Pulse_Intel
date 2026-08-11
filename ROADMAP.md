# Roadmap

Pulse Intelligence is moving from self-hosted prototype to community-maintained open-source
platform. The roadmap favors practical analyst workflows over broad, generic feature lists.

## Phase 8: Hardening

- Add large-table partitioning guidance for high-volume indicator deployments.
- Expand API examples and client snippets.
- Add more defensive feed parser tests and fixtures.
- Continue dependency review and security hardening.
- Improve backup restore smoke testing in non-production environments.

## Near-Term Community Work

- Add vendor blog feed parsers with fixtures.
- Add SOAR and analyst notebook examples.
- Improve public demo data so new users can evaluate the platform quickly.
- Add screenshots and short workflow clips to the documentation site.
- Collect feedback from junior analysts and SOC users.

## Later Work

- Streaming exports for very large filtered indicator sets.
- Role-scoped API write endpoints for controlled automation.
- More ATT&CK Navigator layer options.
- Deployment templates for common VPS and container environments.
- Optional OpenTelemetry instrumentation.

## Non-Goals For Now

- Replacing MISP, OpenCTI, or full case-management platforms.
- Storing secrets or provider credentials in exported backups without operator controls.
- Treating AI-generated analysis as authoritative without analyst review.
