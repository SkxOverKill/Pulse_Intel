# Threat Hunting

Pulse Intelligence hunts are structured indicator queries. They are designed for repeatable
analyst workflows: define a condition set, preview current matches, schedule it, and alert only
when new indicators match.

## Query Builder

The builder supports:

- Indicator type, severity, TLP, confidence, value, tag, source, first seen, and last seen.
- ATT&CK technique and tactic fields through linked actors and campaigns.
- `all` matching for AND logic and `any` matching for OR logic.
- Built-in templates for common CTI workflows.

Whitelisted indicators are never matched by hunts.

## Built-In Templates

- High-confidence network IOCs
- Critical CVEs
- Ransomware tagged IOCs
- Recent high-severity indicators
- Initial access network IOCs

Templates are starting points. Review the conditions before saving and tune dates, tags, and
confidence thresholds for the environment.

## SIEM Query Drafts

The builder and hunt detail page generate portable query drafts for:

- Microsoft Sentinel / Kusto Query Language
- Splunk Search Processing Language
- Elastic/Lucene syntax

These drafts target normalized Pulse indicator fields such as `type`, `value`, `severity`,
`confidence`, `tags`, `source`, `attack.technique`, and `attack.tactic`. Adapt field names to
the destination SIEM schema before production use.

## Exporting Matches

Saved hunt matches can be exported from the hunt detail page. The export reuses the same safe
indicator formats as the main IOC export flow:

- CSV
- STIX 2.1
- MISP JSON
- Snort/Suricata rules

Exports are capped to protect the web process from very large downloads. Streaming exports are
tracked in the roadmap for large deployments.

## Alert Semantics

Scheduled hunts compare the current match set against the previous run. Alerts are created only
when a hunt has `Alert on new matches` enabled and new indicators are found.

A first run treats all matches as new, which establishes the hunt baseline.
