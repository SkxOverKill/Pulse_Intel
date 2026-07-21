import type { IndicatorType } from "@/generated/prisma/enums";

/**
 * Whitelisting.
 *
 * The classic TIP failure is exporting `8.8.8.8` to a firewall because some feed
 * listed it as a C2 resolver. Anything matching here is flagged `whitelisted` at
 * ingest — still stored (so an analyst can see the feed claimed it) but never
 * exported or alerted on.
 */

// RFC 1918 private, loopback, link-local, CGNAT, multicast, broadcast.
const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^(22[4-9]|23\d)\./,
  /^0\.0\.0\.0$/,
  /^255\.255\.255\.255$/,
];

// Well-known public resolvers. Malware does use them, but blocking them breaks
// the network far worse than the threat they represent.
const PUBLIC_RESOLVERS = new Set([
  "8.8.8.8",
  "8.8.4.4",
  "1.1.1.1",
  "1.0.0.1",
  "9.9.9.9",
  "149.112.112.112",
  "208.67.222.222",
  "208.67.220.220",
]);

/**
 * Domains that are load-bearing infrastructure. Deliberately conservative — this
 * list should hold things that would cause an outage if blocked, not merely
 * popular sites. Phase 5 supplements it with a Tranco top-N list.
 */
const INFRASTRUCTURE_DOMAINS = [
  "google.com",
  "googleapis.com",
  "gstatic.com",
  "microsoft.com",
  "windows.com",
  "windowsupdate.com",
  "office.com",
  "office365.com",
  "live.com",
  "apple.com",
  "icloud.com",
  "amazonaws.com",
  "cloudfront.net",
  "azure.com",
  "azureedge.net",
  "akamai.net",
  "akamaiedge.net",
  "cloudflare.com",
  "cloudflare-dns.com",
  "github.com",
  "githubusercontent.com",
  "mozilla.org",
  "digicert.com",
  "verisign.com",
  "letsencrypt.org",
];

const EMPTY_FILE_HASHES = new Set([
  // Empty file — appears constantly in sandbox output and means nothing.
  "d41d8cd98f00b204e9800998ecf8427e",
  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
]);

function domainMatches(value: string, base: string): boolean {
  return value === base || value.endsWith(`.${base}`);
}

/** Returns the reason the indicator is whitelisted, or null if it is not. */
export function whitelistReason(
  type: IndicatorType,
  normalizedValue: string,
): string | null {
  switch (type) {
    case "IPV4":
      if (PRIVATE_V4.some((re) => re.test(normalizedValue))) {
        return "Private, loopback or reserved address space";
      }
      if (PUBLIC_RESOLVERS.has(normalizedValue)) {
        return "Well-known public DNS resolver";
      }
      return null;

    case "IPV6":
      if (
        normalizedValue === "::1" ||
        normalizedValue.startsWith("fe80:") ||
        normalizedValue.startsWith("fc") ||
        normalizedValue.startsWith("fd")
      ) {
        return "Private, loopback or link-local address space";
      }
      return null;

    case "DOMAIN":
      if (INFRASTRUCTURE_DOMAINS.some((d) => domainMatches(normalizedValue, d))) {
        return "Core internet or OS infrastructure domain";
      }
      if (normalizedValue.endsWith(".local") || normalizedValue.endsWith(".internal")) {
        return "Internal-only TLD";
      }
      return null;

    case "URL":
      try {
        const host = new URL(normalizedValue).hostname;
        if (INFRASTRUCTURE_DOMAINS.some((d) => domainMatches(host, d))) {
          return "Core internet or OS infrastructure domain";
        }
      } catch {
        // Unparseable URL is not grounds for whitelisting.
      }
      return null;

    case "MD5":
    case "SHA1":
    case "SHA256":
      if (EMPTY_FILE_HASHES.has(normalizedValue)) {
        return "Hash of an empty file";
      }
      return null;

    default:
      return null;
  }
}

export function isWhitelisted(type: IndicatorType, normalizedValue: string): boolean {
  return whitelistReason(type, normalizedValue) !== null;
}
