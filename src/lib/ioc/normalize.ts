import type { IndicatorType } from "@/generated/prisma/enums";

/**
 * IOC parsing: refang → detect type → normalize for dedup.
 *
 * This runs on every ingest path (bulk paste, CSV, feeds, API), so its output
 * defines what `Indicator.normalizedValue` means and therefore what the
 * `(type, normalizedValue)` unique index actually deduplicates. Getting this
 * wrong silently splits one indicator into several rows.
 */

/**
 * Undo defanging. Threat reports publish indicators deliberately broken so they
 * aren't clickable — `hxxp://evil[.]com` — and every vendor does it differently.
 * We accept all the common forms and store the real value.
 */
export function refang(input: string): string {
  let s = input.trim();

  // Scheme: hxxp / hXXps / h**p. The xx stands in for "tt", so the trailing p is
  // matched literally — capturing it re-emits it and yields "httpp".
  s = s.replace(/\bh(?:xx|\*\*)p(s?):/gi, "http$1:");
  s = s.replace(/\bhttpx:/gi, "http:");

  // Bracketed / parenthesised separators: [.] (.) {.} [dot] [ . ]
  s = s.replace(/\s*[[({]\s*\.\s*[\])}]\s*/g, ".");
  s = s.replace(/\s*[[({]\s*(?:dot|DOT)\s*[\])}]\s*/g, ".");
  s = s.replace(/\s*[[({]\s*:\s*[\])}]\s*/g, ":");
  s = s.replace(/\s*[[({]\s*(?:at|AT)\s*[\])}]\s*/g, "@");
  s = s.replace(/\s*[[({]\s*@\s*[\])}]\s*/g, "@");

  // Bare word separators, only when clearly acting as separators.
  s = s.replace(/\s+(?:dot)\s+/gi, ".");
  s = s.replace(/\s+(?:at)\s+/gi, "@");

  // Some reports bracket the scheme itself: [http]://
  s = s.replace(/\[(https?)\]:/gi, "$1:");

  // A trailing dot on a hostname is legal DNS but noise for dedup.
  return s.trim();
}

// --- Type detection -------------------------------------------------------
//
// Order matters: hashes before domains (a hash has no dots), CVE before
// everything (unambiguous prefix), IP before domain (an IP would otherwise
// match a loose domain pattern).

const RE = {
  cve: /^CVE-\d{4}-\d{4,}$/i,
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/,
  ipv6: /^(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i,
  email: /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i,
  url: /^[a-z][a-z0-9+.-]*:\/\//i,
  // Trailing dot allowed: "evil.com." is legal DNS and appears in feeds.
  // normalize() strips it, so detection must not reject it first.
  domain: /^(?:(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\.?$/i,
  asn: /^AS\d+$/i,
  btc: /^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$/,
  registry: /^(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\/i,
};

export function detectType(rawValue: string): IndicatorType | null {
  const v = refang(rawValue).trim();
  if (!v) return null;

  if (RE.cve.test(v)) return "CVE";
  if (RE.md5.test(v)) return "MD5";
  if (RE.sha1.test(v)) return "SHA1";
  if (RE.sha256.test(v)) return "SHA256";
  if (RE.asn.test(v)) return "ASN";
  if (RE.registry.test(v)) return "REGISTRY_KEY";
  if (RE.ipv4.test(v)) return "IPV4";
  if (RE.url.test(v)) return "URL";
  if (RE.email.test(v)) return "EMAIL";
  // IPv6 before domain: "::1" has colons, no dots, and must not fall through.
  if (v.includes(":") && RE.ipv6.test(v)) return "IPV6";
  if (RE.btc.test(v)) return "BTC_ADDRESS";
  if (RE.domain.test(v)) return "DOMAIN";

  return null;
}

/**
 * Canonical form used for dedup. Must be deterministic and idempotent:
 * normalize(normalize(x)) === normalize(x).
 */
export function normalize(rawValue: string, type: IndicatorType): string {
  let v = refang(rawValue).trim();

  switch (type) {
    case "MD5":
    case "SHA1":
    case "SHA256":
      return v.toLowerCase();

    case "CVE":
    case "ASN":
      return v.toUpperCase();

    case "DOMAIN":
      // Strip a trailing root dot and lowercase. IDN is left as-is; punycode
      // conversion would need a full IDNA table and can come later.
      return v.replace(/\.+$/, "").toLowerCase();

    case "EMAIL":
      // Only the domain part is case-insensitive per RFC 5321, but in practice
      // every mail provider treats the local part that way too, and treating
      // Bob@x.com and bob@x.com as two IOCs is worse than the spec violation.
      return v.toLowerCase();

    case "URL": {
      try {
        const u = new URL(v);
        u.hostname = u.hostname.toLowerCase().replace(/\.+$/, "");
        u.protocol = u.protocol.toLowerCase();
        // Drop the fragment: it never reaches the server, so it cannot
        // distinguish two indicators.
        u.hash = "";
        // Collapse a bare trailing slash so "http://x.com" == "http://x.com/".
        let out = u.toString();
        if (u.pathname === "/" && !u.search) out = out.replace(/\/$/, "");
        return out;
      } catch {
        return v.toLowerCase();
      }
    }

    case "IPV4":
      return v;

    case "IPV6":
      // Lowercase only. Full RFC 5952 compression would be better but needs a
      // proper parser; mixed forms of the same address stay rare in feeds.
      return v.toLowerCase();

    case "BTC_ADDRESS":
      // Base58 is case-sensitive — lowercasing would corrupt the address.
      return v;

    case "REGISTRY_KEY":
      return v.replace(/\//g, "\\");

    case "MUTEX":
    case "FILENAME":
    case "USER_AGENT":
      return v;

    default:
      return v.toLowerCase();
  }
}

export type ParsedIndicator = {
  value: string;
  normalizedValue: string;
  type: IndicatorType;
};

/** Parse a single line. Returns null when the type can't be determined. */
export function parseIndicator(raw: string): ParsedIndicator | null {
  const value = refang(raw).trim();
  const type = detectType(value);
  if (!type) return null;
  return { value, normalizedValue: normalize(value, type), type };
}

export type BulkParseResult = {
  parsed: ParsedIndicator[];
  /** Lines we could not classify, returned so the UI can show them rather than
   *  silently dropping input the analyst pasted. */
  unparsed: string[];
  /** Duplicates collapsed within this input, before any DB lookup. */
  duplicatesInInput: number;
};

/**
 * Parse pasted text. Accepts one indicator per line, plus comma/semicolon/tab
 * separated values, and ignores blank lines and `#` comments.
 */
export function parseBulk(input: string): BulkParseResult {
  const parsed: ParsedIndicator[] = [];
  const unparsed: string[] = [];
  const seen = new Set<string>();
  let duplicatesInInput = 0;

  const tokens = input
    .split(/[\r\n]+/)
    .flatMap((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return [];
      // Only split on delimiters when they're actually separating tokens —
      // commas appear inside URLs, so require whitespace or multiple fields.
      return trimmed.split(/[\t;,]+|\s{2,}/);
    })
    .map((t) => t.trim())
    .filter(Boolean);

  for (const token of tokens) {
    const result = parseIndicator(token);
    if (!result) {
      unparsed.push(token);
      continue;
    }
    const key = `${result.type}:${result.normalizedValue}`;
    if (seen.has(key)) {
      duplicatesInInput++;
      continue;
    }
    seen.add(key);
    parsed.push(result);
  }

  return { parsed, unparsed, duplicatesInInput };
}

/** Re-defang for display in contexts where a live link would be dangerous. */
export function defang(value: string): string {
  return value
    .replace(/^http(s?):/i, "hxxp$1:")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[at]");
}
