/**
 * Client-safe IOC extractor — runs in the browser with no server round-trip.
 *
 * Designed for the "paste a threat report" use case: analysts copy the full
 * text of a vendor report, paste it, and get every embedded IOC extracted
 * and previewed before submitting. The live preview drives the "OMG" moment —
 * watching the platform parse a Mandiant report in real time and pull out 47
 * IPs, 12 domains, and 8 SHA256 hashes is the thing that converts sceptics.
 *
 * Key design decisions:
 *   - Runs entirely in the browser (no node-only imports). The server-side
 *     normalize.ts handles dedup and storage; this handles discovery.
 *   - Defanging is undone before matching, so hxxp[:]//evil[.]com is found.
 *   - All matches are returned in normalized form — what will be stored,
 *     not what was in the original text.
 *   - Overlapping matches are de-duplicated. If a SHA256 appears five times
 *     in a report, it emits once.
 *   - Type order matters: hashes before domains (a 64-char hex string is a
 *     SHA256, not a domain label), CVE before everything else, IP before domain.
 */

export type ExtractedIndicator = {
  type: string;
  value: string;           // as found in the text (defanged or not)
  normalizedValue: string; // what would be stored
};

export type ExtractionResult = {
  indicators: ExtractedIndicator[];
  byType: Record<string, number>;
  total: number;
  /** Lines that had no extractable IOC — shown so analysts know what was skipped. */
  unparsedCount: number;
};

// --------------------------------------------------------------------------
// Defang reversal — same rules as server-side refang(), kept in sync manually.
// --------------------------------------------------------------------------

function refang(s: string): string {
  s = s.replace(/\bh(?:xx|\*\*)p(s?):/gi, "http$1:");
  s = s.replace(/\bhttpx:/gi, "http:");
  s = s.replace(/\s*[[({]\s*\.\s*[\])}]\s*/g, ".");
  s = s.replace(/\s*[[({]\s*(?:dot|DOT)\s*[\])}]\s*/g, ".");
  s = s.replace(/\s*[[({]\s*:\s*[\])}]\s*/g, ":");
  s = s.replace(/\s*[[({]\s*(?:at|AT)\s*[\])}]\s*/g, "@");
  s = s.replace(/\s*[[({]\s*@\s*[\])}]\s*/g, "@");
  s = s.replace(/\s+(?:dot)\s+/gi, ".");
  s = s.replace(/\s+(?:at)\s+/gi, "@");
  s = s.replace(/\[(https?)\]:/gi, "$1:");
  return s.trim().replace(/\.+$/, "");
}

// --------------------------------------------------------------------------
// Regex patterns for in-text extraction (not line-anchored).
// These are tuned for prose extraction, not line-by-line parsing.
// --------------------------------------------------------------------------

// IPv4 — excluding private ranges for the prose extractor (private IPs in
// text are almost always document formatting noise, not IOCs; analysts
// explicitly pasting a private IP get it through the line-mode parser).
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\[?\.\]?)){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g;

// Domain — rough match for prose extraction; tighten for line mode.
const DOMAIN_PROSE_RE = /\b(?:(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?)){1,}[a-z]{2,63}\b/gi;

// URL — scheme-anchored, handles defanged schemes.
const URL_PROSE_RE = /\b(?:h(?:xx|\*\*)ps?|https?|ftp)(?::\[\/\/\]|:\/\/)\S+/gi;

// Hashes — length-anchored hex strings (order: SHA256 > SHA1 > MD5).
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const SHA1_RE   = /\b[a-f0-9]{40}\b/gi;
const MD5_RE    = /\b[a-f0-9]{32}\b/gi;

// CVE — the unambiguous one.
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;

// BTC addresses (P2PKH / P2SH / bech32).
const BTC_RE = /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{6,87})\b/g;

// Email — simple, avoids false-positive on domain@domain patterns.
const EMAIL_RE = /\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b/gi;

// Mutex — common patterns: looks like \BaseNamedObjects\mutexname or {GUID}.
const MUTEX_RE = /\\BaseNamedObjects\\[^\s,;'"]+/g;

// Registry keys.
const REGKEY_RE = /\b(?:HKEY_[A-Z_]+|HK[CLU]M?)\\[^\s,;'"]{4,}/g;

// User-agent — starts with known tokens; rough, best-effort.
const UA_RE = /(?:Mozilla\/[\d.]+|curl\/[\d.]+|python-requests\/[\d.]+)[^\n"']{10,200}/gi;

// ASN
const ASN_RE = /\bAS\d{1,10}\b/gi;

// --------------------------------------------------------------------------
// Private IP ranges to skip in prose mode.
// --------------------------------------------------------------------------

function isPrivateIp(ip: string): boolean {
  const clean = ip.replace(/\[\.]/g, ".").replace(/\(\.?\)/g, ".");
  const parts = clean.split(".").map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    a === 0
  );
}

// Common TLDs that are actually suffixes on other IOCs or text artifacts.
const NOISE_DOMAINS = new Set([
  "example.com", "example.org", "localhost", "test.com", "invalid",
]);

function isNoiseDomain(domain: string): boolean {
  return NOISE_DOMAINS.has(domain.toLowerCase());
}

// --------------------------------------------------------------------------
// Line-mode parser (one IOC per line, the existing bulk-paste behavior).
// --------------------------------------------------------------------------

const LINE_PATTERNS: Array<{ type: string; re: RegExp; normalize?: (v: string) => string }> = [
  { type: "CVE",          re: /^CVE-\d{4}-\d{4,}$/i,          normalize: (v) => v.toUpperCase() },
  { type: "SHA256",       re: /^[a-f0-9]{64}$/i,               normalize: (v) => v.toLowerCase() },
  { type: "SHA1",         re: /^[a-f0-9]{40}$/i,               normalize: (v) => v.toLowerCase() },
  { type: "MD5",          re: /^[a-f0-9]{32}$/i,               normalize: (v) => v.toLowerCase() },
  { type: "BTC_ADDRESS",  re: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-zA-HJ-NP-Z0-9]{6,87}$/ },
  { type: "IPV4",         re: /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/ },
  { type: "IPV6",         re: /^(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i, normalize: (v) => v.toLowerCase() },
  { type: "EMAIL",        re: /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i, normalize: (v) => v.toLowerCase() },
  { type: "URL",          re: /^[a-z][a-z0-9+.-]*:\/\//i,      normalize: (v) => v.toLowerCase() },
  { type: "DOMAIN",       re: /^(?:(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\.?$/i, normalize: (v) => v.toLowerCase().replace(/\.$/, "") },
  { type: "MUTEX",        re: /\\BaseNamedObjects\\/,           normalize: (v) => v },
  { type: "REGISTRY_KEY", re: /^(?:HKEY_[A-Z_]+|HK[CLU]M?)\\/,normalize: (v) => v },
  { type: "USER_AGENT",   re: /^Mozilla\/[\d.]+/,              normalize: (v) => v },
  { type: "ASN",          re: /^AS\d{1,10}$/i,                 normalize: (v) => v.toUpperCase() },
];

function classifyLine(raw: string): { type: string; normalizedValue: string } | null {
  const refanged = refang(raw);
  for (const { type, re, normalize } of LINE_PATTERNS) {
    if (re.test(refanged)) {
      return { type, normalizedValue: normalize ? normalize(refanged) : refanged };
    }
  }
  return null;
}

// --------------------------------------------------------------------------
// Prose extractor — finds IOCs embedded in paragraphs of text.
// --------------------------------------------------------------------------

function extractFromProse(text: string): ExtractedIndicator[] {
  const seen = new Set<string>();
  const results: ExtractedIndicator[] = [];

  function add(type: string, raw: string, normalized: string) {
    const key = `${type}:${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    results.push({ type, value: raw, normalizedValue: normalized });
  }

  // CVE first — unambiguous.
  for (const m of text.matchAll(CVE_RE)) {
    add("CVE", m[0], m[0].toUpperCase());
  }

  // Hashes — longest first to avoid SHA1 matching inside SHA256.
  for (const m of text.matchAll(SHA256_RE)) {
    add("SHA256", m[0], m[0].toLowerCase());
  }
  for (const m of text.matchAll(SHA1_RE)) {
    const key = m[0].toLowerCase();
    if (!seen.has(`SHA256:${key}`)) add("SHA1", m[0], key);
  }
  for (const m of text.matchAll(MD5_RE)) {
    const key = m[0].toLowerCase();
    if (!seen.has(`SHA256:${key}`) && !seen.has(`SHA1:${key}`)) {
      add("MD5", m[0], key);
    }
  }

  // URLs — before domains to avoid domain matching on just the hostname part.
  for (const m of text.matchAll(URL_PROSE_RE)) {
    const refanged = refang(m[0]);
    try {
      const url = new URL(refanged);
      add("URL", m[0], url.toString().toLowerCase());
    } catch {
      add("URL", m[0], refanged.toLowerCase());
    }
  }

  // Emails — before domains (user@host.tld would also match domain).
  for (const m of text.matchAll(EMAIL_RE)) {
    const refanged = refang(m[0]);
    add("EMAIL", m[0], refanged.toLowerCase());
  }

  // IPv4
  for (const m of text.matchAll(IPV4_RE)) {
    const clean = refang(m[0]);
    if (isPrivateIp(clean)) continue;
    add("IPV4", m[0], clean);
  }

  // Domains — very loose in prose mode; skip things that look like they were
  // already matched as URL/email, and skip common noise.
  for (const m of text.matchAll(DOMAIN_PROSE_RE)) {
    const clean = refang(m[0]).toLowerCase().replace(/\.$/, "");
    if (!clean.includes(".")) continue;
    if (isNoiseDomain(clean)) continue;
    // Skip if this string was already matched as part of a URL or email.
    const context = text.substring(Math.max(0, m.index! - 10), m.index!);
    if (/[:@/]$/.test(context)) continue;
    // Must have at least one dot with a recognizable TLD (2-6 chars).
    if (!/\.[a-z]{2,6}$/i.test(clean)) continue;
    const key = `URL:${clean}`;
    if ([...seen].some((s) => s.includes(clean))) continue;
    add("DOMAIN", m[0], clean);
  }

  // BTC addresses
  for (const m of text.matchAll(BTC_RE)) {
    add("BTC_ADDRESS", m[0], m[0]);
  }

  // Registry keys
  for (const m of text.matchAll(REGKEY_RE)) {
    add("REGISTRY_KEY", m[0], m[0]);
  }

  // Mutexes
  for (const m of text.matchAll(MUTEX_RE)) {
    add("MUTEX", m[0], m[0]);
  }

  // User-agents
  for (const m of text.matchAll(UA_RE)) {
    add("USER_AGENT", m[0], m[0]);
  }

  // ASNs
  for (const m of text.matchAll(ASN_RE)) {
    add("ASN", m[0], m[0].toUpperCase());
  }

  return results;
}

// --------------------------------------------------------------------------
// Main export
// --------------------------------------------------------------------------

/**
 * Extract IOCs from arbitrary text.
 *
 * Two modes, automatically selected:
 *
 * - **Line mode**: text that looks like a structured IOC list (one per line,
 *   maybe comma/tab separated, the existing import form behavior). Produces
 *   the most reliable results for clean exports.
 *
 * - **Prose mode**: text that looks like a paragraph / report (longer average
 *   line length, multiple sentences). Extracts all embedded IOCs using regex
 *   scanning, skipping private IPs and obvious noise.
 *
 * Both modes are run when `forceMode` is "auto" or omitted, with line-mode
 * results taking precedence (a line that parses cleanly in line-mode is not
 * re-scanned for embedded values).
 */
export function extractIocs(
  text: string,
  opts: { mode?: "line" | "prose" | "auto" } = {},
): ExtractionResult {
  const mode = opts.mode ?? "auto";

  const lines = text
    .split(/[\r\n]+/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));

  // Heuristic: if the average line length is > 120 chars it's prose, not a list.
  const avgLen = lines.reduce((s, l) => s + l.length, 0) / Math.max(1, lines.length);
  const isProse = mode === "prose" || (mode === "auto" && (avgLen > 120 || lines.length < 5));

  const seen = new Set<string>();
  const indicators: ExtractedIndicator[] = [];
  let unparsedCount = 0;

  if (!isProse) {
    // Line mode
    for (const line of lines) {
      // Handle comma/tab-separated values on a single line. Commas inside
      // URLs must not split, so require whitespace after a comma.
      const tokens = line.split(/[\t]+|,\s+/).map((t) => t.trim()).filter(Boolean);
      let lineHit = false;
      for (const token of tokens) {
        const result = classifyLine(token);
        if (!result) continue;
        const key = `${result.type}:${result.normalizedValue}`;
        if (seen.has(key)) continue;
        seen.add(key);
        indicators.push({ type: result.type, value: token, normalizedValue: result.normalizedValue });
        lineHit = true;
      }
      if (!lineHit) unparsedCount++;
    }
  }

  if (isProse) {
    // Prose mode — scan the full text for embedded IOCs.
    const proseHits = extractFromProse(text);
    for (const hit of proseHits) {
      const key = `${hit.type}:${hit.normalizedValue}`;
      if (seen.has(key)) continue;
      seen.add(key);
      indicators.push(hit);
    }
  }

  const byType: Record<string, number> = {};
  for (const ind of indicators) {
    byType[ind.type] = (byType[ind.type] ?? 0) + 1;
  }

  return { indicators, byType, total: indicators.length, unparsedCount };
}
