import type { IndicatorType } from "@/generated/prisma/enums";
import {
  ProviderError,
  ProviderRateLimitError,
  providerFetch,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * GreyNoise Community API — "is this IP mass-scanning the internet or targeted?"
 *
 * This is one of the most operationally valuable enrichment sources a SOC has:
 * it separates opportunistic background noise from purposeful threat activity.
 * A MALICIOUS verdict from VirusTotal on an IP that GreyNoise says is Shodan's
 * crawler is very different from the same VT verdict on an unknown actor.
 *
 * Community tier: free, no key required, ~10k/day limit.
 * Commercial tier: GREYNOISE_API_KEY unlocks the full "quick" endpoint.
 *
 * The Community endpoint returns one of three classifications:
 *   "malicious"   — GreyNoise has tagged this IP as actively malicious
 *   "benign"      — known benign mass-scanner (Shodan, Censys, Google, etc.)
 *   "unknown"     — not in GreyNoise's dataset; this is the interesting case
 *                   for SOC analysts — an unknown IP scanning you is more
 *                   suspicious than a known Shodan crawler doing it.
 *
 * The score mapping deliberately squashes benign mass-scanners to 0 while
 * leaving unknowns at a mild 20 — "not noisy" is a weak positive signal.
 */

type GreyNoiseCommunityResponse = {
  ip: string;
  noise: boolean;       // true = in GreyNoise dataset (scanning the internet)
  riot: boolean;        // true = known benign infrastructure (CDN, DNS, etc.)
  classification?: "malicious" | "benign" | "unknown";
  name?: string;        // human name, e.g. "Shodan.io", "GoogleBot"
  link?: string;        // GreyNoise page for this IP
  last_seen?: string;
  message?: string;     // "This IP is commonly included in RIOT..." etc.
};

type GreyNoiseFullResponse = {
  ip: string;
  seen: boolean;
  classification?: "malicious" | "benign" | "unknown";
  noise: boolean;
  riot: boolean;
  tags?: string[];
  actor?: string;
  vpn?: boolean;
  vpn_service?: string;
  metadata?: {
    country?: string;
    country_code?: string;
    city?: string;
    organization?: string;
    asn?: string;
    category?: string;
  };
  raw_data?: {
    scan?: Array<{ port: number; protocol: string }>;
    web?: { paths?: string[]; useragents?: string[] };
  };
  last_seen?: string;
  first_seen?: string;
};

const KEY = process.env.GREYNOISE_API_KEY;

function buildUrl(ip: string): string {
  // Commercial key → full "quick" endpoint with richer data.
  if (KEY) {
    return `https://api.greynoise.io/v2/noise/quick/${encodeURIComponent(ip)}`;
  }
  // Community endpoint — no key needed.
  return `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
}

function scoreFromClassification(
  classification: string | undefined,
  noise: boolean,
  riot: boolean,
): number {
  // RIOT = known-good infra (Google, Cloudflare, DNS resolvers). Score 0.
  if (riot) return 0;
  switch (classification) {
    case "malicious": return 85;
    // "benign" means a known mass-scanner like Shodan — not innocent, but not
    // targeted. Analysts need to know the context, not a high score.
    case "benign":    return 5;
    // Unknown + noise: actively scanning but classification unclear. Moderate.
    case "unknown":   return noise ? 20 : 15;
    default:          return noise ? 20 : 0;
  }
}

export const greyNoiseProvider: EnrichmentProvider = {
  name: "greynoise",
  label: "GreyNoise",
  // Community: ~10k/day, 1 req/s. Commercial keys get much more.
  quota: { perMinute: 60, perDay: KEY ? 50_000 : 10_000 },
  ttlMs: 12 * 60 * 60 * 1000, // 12h — noise classifications shift fast

  supports(type: IndicatorType) {
    return type === "IPV4";
  },

  isConfigured() {
    // Community tier works without any key; commercial tier unlocks with one.
    return true;
  },

  async lookup(value): Promise<LookupResult> {
    const url = buildUrl(value);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (KEY) headers["key"] = KEY;

    const res = await providerFetch(url, { headers });

    if (res.status === 404) {
      // "not in our dataset" — IP is so obscure GreyNoise has never seen it.
      // That itself is mildly interesting (not a known scanner), score low.
      return {
        verdict: "UNKNOWN",
        score: 10,
        raw: { notInDataset: true, ip: value },
      };
    }

    if (res.status === 429) {
      const retry = Number(res.headers.get("x-rate-limit-reset") ?? 60);
      throw new ProviderRateLimitError("GreyNoise rate limit", retry * 1000);
    }

    if (!res.ok) {
      throw new ProviderError(`GreyNoise HTTP ${res.status}`, res.status);
    }

    const body = KEY
      ? (await res.json()) as GreyNoiseFullResponse
      : (await res.json()) as GreyNoiseCommunityResponse;

    const classification = (body as GreyNoiseCommunityResponse).classification;
    const noise = (body as GreyNoiseCommunityResponse).noise ?? false;
    const riot  = (body as GreyNoiseCommunityResponse).riot  ?? false;

    const score = scoreFromClassification(classification, noise, riot);

    let verdict: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";
    if (score >= 70)      verdict = "MALICIOUS";
    else if (score >= 25) verdict = "SUSPICIOUS";
    else if (riot || classification === "benign") verdict = "BENIGN";
    else                  verdict = "UNKNOWN";

    return { verdict, score, raw: body };
  },
};
