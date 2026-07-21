import {
  ProviderError,
  ProviderRateLimitError,
  providerFetch,
  verdictFromScore,
  type EnrichmentProvider,
  type LookupResult,
} from "@/lib/enrichment/types";

/**
 * AbuseIPDB API v2, free tier: 1,000 checks/day, IP addresses only.
 *
 * Its `abuseConfidenceScore` is already a 0-100 confidence, so it maps onto our
 * score directly with no invented arithmetic.
 *
 * A 1-day TTL rather than VT's 7: abuse reports are a live signal, and an IP's
 * reputation genuinely changes day to day.
 */
export const abuseIpDbProvider: EnrichmentProvider = {
  name: "abuseipdb",
  label: "AbuseIPDB",
  quota: { perDay: 1000 },
  ttlMs: 24 * 60 * 60 * 1000,

  supports(type) {
    return type === "IPV4" || type === "IPV6";
  },

  isConfigured() {
    return Boolean(process.env.ABUSEIPDB_API_KEY);
  },

  async lookup(value): Promise<LookupResult> {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", value);
    url.searchParams.set("maxAgeInDays", "90");

    const res = await providerFetch(url.toString(), {
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY ?? "",
        Accept: "application/json",
      },
    });

    if (res.status === 429) {
      const retry = Number(res.headers.get("retry-after") ?? 3600);
      throw new ProviderRateLimitError("AbuseIPDB quota exceeded", retry * 1000);
    }
    if (!res.ok) {
      throw new ProviderError(`AbuseIPDB HTTP ${res.status}`, res.status);
    }

    const body = (await res.json()) as {
      data?: {
        abuseConfidenceScore?: number;
        totalReports?: number;
        isWhitelisted?: boolean;
      };
    };

    const score = body.data?.abuseConfidenceScore ?? 0;

    // AbuseIPDB maintains its own whitelist of known-good infrastructure. If it
    // says whitelisted, trust that over a low report count — this is exactly the
    // 8.8.8.8 case our own whitelist also guards.
    if (body.data?.isWhitelisted) {
      return { verdict: "BENIGN", score: 0, raw: body };
    }

    return { verdict: verdictFromScore(score), score, raw: body };
  },
};
