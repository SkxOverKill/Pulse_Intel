/**
 * Indicator export formatters — CSV, STIX 2.1, MISP JSON, and Snort/Suricata.
 *
 * Pure and dependency-free (no `db`, no `server-only`): the route handler and a
 * future scheduled-report worker both format the same way. Callers pass an
 * already-filtered set — in particular, **whitelisted indicators must never
 * reach here** (design rule 3: stored so you can see a feed claimed them, but
 * never exported). The query that feeds an export enforces `whitelisted: false`.
 *
 * Formats that only make sense for network observables (Snort) skip the rest
 * with an explicit comment rather than emitting a broken rule — a firewall list
 * that silently drops half its input is worse than one that says what it did.
 */
import type { IndicatorType, Severity, Tlp } from "@/generated/prisma/enums";

export type ExportIndicator = {
  type: IndicatorType;
  value: string;
  normalizedValue: string;
  confidence: number;
  severity: Severity;
  tlp: Tlp;
  tags: string[];
  firstSeen: Date;
  lastSeen: Date;
  expiresAt?: Date | null;
  source?: string | null;
};

export type ExportFormat = "csv" | "stix" | "misp" | "snort";

export const EXPORT_FORMATS: {
  id: ExportFormat;
  label: string;
  extension: string;
  contentType: string;
}[] = [
  { id: "csv", label: "CSV", extension: "csv", contentType: "text/csv" },
  {
    id: "stix",
    label: "STIX 2.1 bundle",
    extension: "json",
    contentType: "application/json",
  },
  {
    id: "misp",
    label: "MISP event JSON",
    extension: "json",
    contentType: "application/json",
  },
  {
    id: "snort",
    label: "Snort / Suricata rules",
    extension: "rules",
    contentType: "text/plain",
  },
];

/** Dispatch to a formatter. Returns the serialized body as a string. */
export function formatExport(
  indicators: ExportIndicator[],
  format: ExportFormat,
): string {
  switch (format) {
    case "csv":
      return toCsv(indicators);
    case "stix":
      return toStixBundle(indicators);
    case "misp":
      return toMispEvent(indicators);
    case "snort":
      return toSnortRules(indicators);
  }
}

// --- CSV -------------------------------------------------------------------

const CSV_COLUMNS = [
  "type",
  "value",
  "confidence",
  "severity",
  "tlp",
  "tags",
  "source",
  "firstSeen",
  "lastSeen",
] as const;

/**
 * CSV injection / CWE-1236: an indicator value comes from a feed, so it is
 * attacker-influenced. Excel and Google Sheets evaluate a leading `=`, `+`,
 * `-`, `@` (and a leading tab/CR) as a formula when the export is opened —
 * a feed could ship an IOC that becomes a live formula in an analyst's
 * spreadsheet. Neutralize the first character with a leading single quote:
 * the value keeps its content, the spreadsheet treats it as text.
 */
const CSV_FORMULA_RE = /^[=+\-@\t\r]/;

function csvCell(value: string): string {
  const safe = CSV_FORMULA_RE.test(value) ? `'${value}` : value;
  if (/[",\r\n]/.test(safe)) return `"${safe.replace(/"/g, '""')}"`;
  return safe;
}

export function toCsv(indicators: ExportIndicator[]): string {
  const rows = [CSV_COLUMNS.join(",")];
  for (const i of indicators) {
    rows.push(
      [
        i.type,
        i.value,
        String(i.confidence),
        i.severity,
        i.tlp,
        i.tags.join("|"),
        i.source ?? "",
        i.firstSeen.toISOString(),
        i.lastSeen.toISOString(),
      ]
        .map(csvCell)
        .join(","),
    );
  }
  // Trailing newline: many tools treat a missing final newline as a truncated
  // file. CRLF per RFC 4180.
  return rows.join("\r\n") + "\r\n";
}

// --- STIX 2.1 --------------------------------------------------------------

/**
 * Maps an indicator to a STIX pattern, or null if the type has no clean
 * observable representation. Null-pattern indicators are omitted from the
 * bundle rather than emitted as an invalid pattern a consumer would reject.
 */
export function stixPattern(i: ExportIndicator): string | null {
  const v = escapeStixString(i.value);
  switch (i.type) {
    case "IPV4":
      return `[ipv4-addr:value = '${v}']`;
    case "IPV6":
      return `[ipv6-addr:value = '${v}']`;
    case "DOMAIN":
      return `[domain-name:value = '${v}']`;
    case "URL":
      return `[url:value = '${v}']`;
    case "MD5":
      return `[file:hashes.MD5 = '${v}']`;
    case "SHA1":
      return `[file:hashes.'SHA-1' = '${v}']`;
    case "SHA256":
      return `[file:hashes.'SHA-256' = '${v}']`;
    case "EMAIL":
      return `[email-addr:value = '${v}']`;
    case "REGISTRY_KEY":
      return `[windows-registry-key:key = '${v}']`;
    case "MUTEX":
      return `[mutex:name = '${v}']`;
    case "FILENAME":
      return `[file:name = '${v}']`;
    case "ASN": {
      const num = i.value.replace(/^AS/i, "");
      return /^\d+$/.test(num) ? `[autonomous-system:number = ${num}]` : null;
    }
    // CVE is a STIX vulnerability SDO, not an observable pattern; USER_AGENT and
    // BTC_ADDRESS have no standard observable. Omitted rather than faked.
    case "CVE":
    case "USER_AGENT":
    case "BTC_ADDRESS":
      return null;
  }
}

function escapeStixString(value: string): string {
  // STIX string literals escape backslash and single-quote.
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

const TLP_TO_STIX_MARKING: Record<Tlp, string> = {
  CLEAR: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
  GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
  AMBER_STRICT: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
  RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
};

/**
 * Deterministic STIX id from the indicator's stable dedup key, so re-exporting
 * the same indicator yields the same id (idempotent for consumers) without
 * needing to persist one.
 */
function stixId(i: ExportIndicator): string {
  return `indicator--${uuidFromSeed(`${i.type}:${i.normalizedValue}`)}`;
}

export function toStixBundle(indicators: ExportIndicator[]): string {
  const objects = indicators
    .map((i) => {
      const pattern = stixPattern(i);
      if (!pattern) return null;
      return {
        type: "indicator",
        spec_version: "2.1",
        id: stixId(i),
        created: i.firstSeen.toISOString(),
        modified: i.lastSeen.toISOString(),
        valid_from: i.firstSeen.toISOString(),
        ...(i.expiresAt ? { valid_until: i.expiresAt.toISOString() } : {}),
        name: `${i.type} ${i.value}`,
        pattern,
        pattern_type: "stix",
        confidence: i.confidence,
        labels: i.tags.length ? i.tags : ["malicious-activity"],
        object_marking_refs: [TLP_TO_STIX_MARKING[i.tlp]],
      };
    })
    .filter((o): o is NonNullable<typeof o> => o !== null);

  return JSON.stringify(
    {
      type: "bundle",
      id: `bundle--${uuidFromSeed(`pulse-export-${indicators.length}-${Date.now()}`)}`,
      objects,
    },
    null,
    2,
  );
}

// --- MISP ------------------------------------------------------------------

const MISP_ATTRIBUTE_TYPE: Record<IndicatorType, string> = {
  IPV4: "ip-dst",
  IPV6: "ip-dst",
  DOMAIN: "domain",
  URL: "url",
  MD5: "md5",
  SHA1: "sha1",
  SHA256: "sha256",
  EMAIL: "email-src",
  CVE: "vulnerability",
  BTC_ADDRESS: "btc",
  REGISTRY_KEY: "regkey",
  MUTEX: "mutex",
  FILENAME: "filename",
  USER_AGENT: "user-agent",
  ASN: "AS",
};

export function toMispEvent(indicators: ExportIndicator[]): string {
  const attributes = indicators.map((i) => ({
    type: MISP_ATTRIBUTE_TYPE[i.type],
    category: mispCategory(i.type),
    value: i.value,
    to_ids: i.confidence >= 50,
    comment: i.source ? `source: ${i.source}` : "",
    Tag: [
      { name: `tlp:${i.tlp.toLowerCase().replace("_", "-")}` },
      ...i.tags.map((t) => ({ name: t })),
    ],
  }));

  return JSON.stringify(
    {
      Event: {
        info: `Pulse Intelligence export — ${indicators.length} indicator(s)`,
        date: new Date().toISOString().slice(0, 10),
        // MISP threat levels: 1 high … 4 undefined. We export at 2 (medium).
        threat_level_id: "2",
        analysis: "2",
        Attribute: attributes,
      },
    },
    null,
    2,
  );
}

function mispCategory(type: IndicatorType): string {
  switch (type) {
    case "IPV4":
    case "IPV6":
    case "DOMAIN":
    case "URL":
      return "Network activity";
    case "MD5":
    case "SHA1":
    case "SHA256":
    case "FILENAME":
      return "Payload delivery";
    case "EMAIL":
      return "Payload delivery";
    case "CVE":
      return "External analysis";
    case "REGISTRY_KEY":
    case "MUTEX":
      return "Artifacts dropped";
    default:
      return "Other";
  }
}

// --- Snort / Suricata ------------------------------------------------------

/**
 * Emits rules for network-observable types only (IP, domain, URL). Everything
 * else is listed in a trailing comment so the operator knows what was left out,
 * not silently dropped. SIDs start at a private-range base to avoid colliding
 * with distributed rulesets.
 */
const SNORT_SID_BASE = 3_000_000;

export function toSnortRules(indicators: ExportIndicator[]): string {
  const lines: string[] = [
    "# Pulse Intelligence export — Snort/Suricata rules",
    `# ${indicators.length} indicator(s) considered; only network observables become rules.`,
    "",
  ];

  let sid = SNORT_SID_BASE;
  const skipped: ExportIndicator[] = [];

  for (const i of indicators) {
    const rule = snortRule(i, sid);
    if (rule) {
      lines.push(rule);
      sid++;
    } else {
      skipped.push(i);
    }
  }

  if (skipped.length) {
    lines.push("");
    lines.push(`# ${skipped.length} non-network indicator(s) not expressible as rules:`);
    for (const i of skipped) lines.push(`#   ${i.type} ${i.value}`);
  }

  return lines.join("\n") + "\n";
}

function snortRule(i: ExportIndicator, sid: number): string | null {
  const msg = `Pulse IOC ${i.type} ${i.value} (sev ${i.severity})`.replace(/"/g, "'");
  switch (i.type) {
    case "IPV4":
    case "IPV6":
      return `alert ip $HOME_NET any -> ${i.value} any (msg:"${msg}"; sid:${sid}; rev:1;)`;
    case "DOMAIN":
      return `alert dns $HOME_NET any -> any any (msg:"${msg}"; dns.query; content:"${i.normalizedValue}"; nocase; sid:${sid}; rev:1;)`;
    case "URL": {
      const path = urlPath(i.value);
      return `alert http $HOME_NET any -> any any (msg:"${msg}"; http.uri; content:"${path}"; nocase; sid:${sid}; rev:1;)`;
    }
    default:
      return null;
  }
}

function urlPath(url: string): string {
  try {
    const u = new URL(url);
    return (u.pathname + u.search) || "/";
  } catch {
    return url;
  }
}

// --- shared ----------------------------------------------------------------

/**
 * Deterministic RFC-4122-shaped UUID (v4 layout) from a seed string. Not
 * cryptographic — just a stable, well-formed id so the same input yields the
 * same STIX id across exports without persisting one.
 */
function uuidFromSeed(seed: string): string {
  let h = 0x811c9dc5;
  const bytes: number[] = [];
  for (let n = 0; n < 16; n++) {
    for (let k = 0; k < seed.length; k++) {
      h ^= seed.charCodeAt(k) + n * 131;
      h = Math.imul(h, 0x01000193);
    }
    bytes.push((h >>> ((n % 4) * 8)) & 0xff);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}
