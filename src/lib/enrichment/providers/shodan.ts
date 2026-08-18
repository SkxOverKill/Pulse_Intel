import type { IndicatorType } from "@/generated/prisma/enums";
import { getSecret } from "@/lib/enrichment/secrets";
import {
  ProviderError,
  ProviderRateLimitError,
  providerFetch,
  verdictFromScore,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * Shodan InternetDB — free, no API key, no rate-limit headers, stable.
 *
 * Why InternetDB over the full Shodan API:
 *   - No key required → works out of the box for every deployment.
 *   - Covers every public IP with open ports, CPEs, vulns, hostnames, tags.
 *   - The full API (api.shodan.io/shodan/host/:ip) requires a paid plan for
 *     history and org lookups; most teams don't have one.
 *
 * Scoring rationale:
 *   - Known CVEs on the host push the score up. Critical (CVSS ≥ 9) get a
 *     hard floor of 60 — an internet-facing host with an actively exploited
 *     vuln that's been KEV-listed is never "benign" context.
 *   - Tags from Shodan itself (honeypot, vpn, tor, cloud) are surfaced in the
 *     raw payload so analysts can see them on the enrichment card.
 *   - Port count is not scored — 65535 open ports on a scanner is noise.
 *
 * SHODAN_API_KEY (optional): enables the full /shodan/host/:ip endpoint with
 * org, ASN, geo, and historical scan data. Without a key, InternetDB is used.
 */

type ShodanInternetDb = {
  ip: string;
  ports:      number[];
  cpes:       string[];
  vulns:      string[];   // CVE IDs, e.g. ["CVE-2021-44228"]
  hostnames:  string[];
  tags:       string[];
};

type ShodanFullHost = {
  ip_str:       string;
  hostnames:    string[];
  ports:        number[];
  vulns?:       Record<string, { cvss?: number; summary?: string }>;
  tags?:        string[];
  org?:         string;
  asn?:         string;
  country_name?: string;
  city?:        string;
  isp?:         string;
  data?:        Array<{
    port: number;
    transport: string;
    product?: string;
    version?: string;
    cpe?: string[];
  }>;
};

function buildUrl(ip: string, key?: string): string {
  if (key) {
    return `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${key}`;
  }
  return `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;
}

function scoreFromShodanData(vulns: string[], tags: string[]): number {
  if (vulns.length === 0) return 0;

  // Score rises with vuln count, capped at 80 before tag bonuses.
  let base = Math.min(80, 10 + vulns.length * 8);

  // Honeypot tag means Shodan believes it's intentionally exposed — lower
  // the score; the "vulns" may be intentional lures.
  if (tags.includes("honeypot")) base = Math.min(base, 30);

  return base;
}

function scoreFromFullHost(host: ShodanFullHost): number {
  const vulnMap = host.vulns ?? {};
  const vulnEntries = Object.values(vulnMap);
  if (vulnEntries.length === 0) return 0;

  // Critical CVSS ≥ 9.0 on an internet-facing host is the worst case.
  const hasCritical = vulnEntries.some((v) => (v.cvss ?? 0) >= 9.0);
  const hasHigh     = vulnEntries.some((v) => (v.cvss ?? 0) >= 7.0);

  if (hasCritical)   return 75;
  if (hasHigh)       return 55;
  return Math.min(40, 10 + vulnEntries.length * 5);
}

export const shodanProvider: EnrichmentProvider = {
  name: "shodan",
  label: "Shodan",
  // InternetDB has no documented rate limit; being polite at 30/min.
  // Full API: free tier allows 1 req/s.
  get quota() {
    return { perMinute: getSecret("shodan") ? 60 : 30 };
  },
  ttlMs: 48 * 60 * 60 * 1000, // 48h — port data changes slowly

  supports(type: IndicatorType) {
    return type === "IPV4";
  },

  isConfigured() {
    // InternetDB works without a key; always available.
    return true;
  },

  async lookup(value): Promise<LookupResult> {
    const key = getSecret("shodan");
    const url = buildUrl(value, key);
    const res = await providerFetch(url);

    if (res.status === 404) {
      // InternetDB 404 = IP has no open ports / not indexed. Clean signal.
      return { verdict: "UNKNOWN", score: 0, raw: { notIndexed: true, ip: value } };
    }

    if (res.status === 429) {
      const retry = Number(res.headers.get("retry-after") ?? 60);
      throw new ProviderRateLimitError("Shodan rate limit", retry * 1000);
    }

    if (!res.ok) {
      throw new ProviderError(`Shodan HTTP ${res.status}`, res.status);
    }

    if (key) {
      const body = (await res.json()) as ShodanFullHost;
      const score = scoreFromFullHost(body);
      return { verdict: verdictFromScore(score), score, raw: body };
    }

    const body = (await res.json()) as ShodanInternetDb;
    const score = scoreFromShodanData(body.vulns ?? [], body.tags ?? []);
    return { verdict: verdictFromScore(score), score, raw: body };
  },
};
