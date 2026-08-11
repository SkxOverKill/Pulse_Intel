# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for vulnerabilities.

Report security issues through GitHub private vulnerability reporting:

https://github.com/SkxOverKill/Pulse_Intel/security/advisories/new

Include:

- Affected version or commit.
- Steps to reproduce.
- Impact.
- Any logs, screenshots, or proof-of-concept details needed to validate the issue.

## Secrets

Pulse Intelligence uses API keys for enrichment providers and secret values for sessions and
future credential encryption. Keep these in `.env` or your deployment secret store only.

If a real key was committed, shared in chat, or exposed through logs, rotate it immediately.
